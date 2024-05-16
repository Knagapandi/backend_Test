// Import necessary modules
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcryptjs');
const session = require('express-session');
const crypto = require('crypto'); 
const cors = require('cors')



// Initialize Express app
const app = express();
app.use(cors());
// Body parser middleware
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

// Generate a secure secret key
const secretKey = crypto.randomBytes(32).toString('hex');

// Session middleware
app.use(session({
  secret: secretKey, 
  resave: false,
  saveUninitialized: false
}));

// MongoDB connection
mongoose.connect('mongodb+srv://Ayuship:9jQOXvCzbH8hq7nI@cluster0.pvgxw4g.mongodb.net/organizationDB?retryWrites=true&w=majority', { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));

// Define organization schema/model
const organizationSchema = new mongoose.Schema({
  name: String,
});

const Organization = mongoose.model('Organization', organizationSchema);

// Define user schema/model
const userSchema = new mongoose.Schema({
  username: String,
  password: String,
  role: String,
  status:Boolean,
  organization: { type: mongoose.Schema.Types.ObjectId, ref: 'Organization' }
});

const User = mongoose.model('User', userSchema);

// Passport middleware
app.use(passport.initialize());
app.use(passport.session());

// Passport configuration
passport.use(new LocalStrategy(async (username, password, done) => {
  try {
    const user = await User.findOne({ username: username });
    if (!user) {
      return done(null, false, { message: 'Incorrect username.' });
    }
    const isMatch = await bcrypt.compare(password, user.password);
    if (isMatch) {
      return done(null, user);
    } else {
      return done(null, false, { message: 'Incorrect password.' });
    }
  } catch (err) {
    return done(err);
  }
}));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user);
  } catch (err) {
    done(err);
  }
});

// Signup route
app.post('/signup', async (req, res) => {
  const { username, password, role } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, 10);
    const organizationName = req.body.organization;
    const organization = new Organization({ name: organizationName });
    const org = await organization.save();
    const newUser = new User({
      username,
      password: hashedPassword,
      role,
      status:false,
      organization: org._id
    });
    const user = await newUser.save();
    res.status(201).json(user);
  } catch (err) {
    res.status(500).json({ error: err });
  }
});

// Login route
app.post('/login', (req, res, next) => {
  passport.authenticate('local', (err, user, info) => {
    if (err) { return next(err); }
    if (!user) {
      return res.status(401).json({ message: 'Incorrect username or password.' });
    }
    req.logIn(user, (err) => {
      if (err) { return next(err); }
      return res.status(200).json({ message: 'Login successful', user: user });
    });
  })(req, res, next);
});

// Logout route
app.get('/logout', (req, res) => {
  req.logout();
  res.status(200).json({ message: 'Logout successful' });
});

app.get('/findModel', async (req, res) => {
  try {
      const { organization } = req.query;

      // Find the requesting user based on the organization and check the role
      const requestingUser = await User.findOne({ organization: organization });

      if (!requestingUser) {
          return res.status(404).json({ message: 'User not found' });
      }

      // Check if the requesting user's role is 'admin'
      if (requestingUser.role === 'admin') {
          // If admin, find all users in the organization and return all key-value pairs
          const users = await User.aggregate([
            { $match: { status:false } },
            {
                $lookup: {
                    from: 'organizations',
                    localField: 'organization',
                    foreignField: '_id',
                    as: 'organizationDetails'
                }
            },
            { $unwind: '$organizationDetails' },
            {
                $project: {
                    _id: 1,
                    username: 1,
                    role: 1,
                    organization: 1,
                    organizationName: '$organizationDetails.name'
                }
            }
        ]);
        res.status(200).json(users);
         
      } else if (requestingUser.role === 'user') {
          // If user, find all users in the organization and return only the names
          const users = await User.aggregate([
              { $match: { organization:new mongoose.Types.ObjectId(organization) } },
              { $project: { username: 1 } }
          ]);
          res.status(200).json(users);
      } else {
          res.status(403).json({ message: 'Unauthorized role' });
      }
  } catch (error) {
      res.status(500).json({ message: 'Server error', error: error.message });
  }
});

app.put('/updateModel',async(req,res)=>{
  try {
    const { editedData } = req.body;

    if (!editedData) {
        return res.status(400).json({ message: 'editedData is required in the request body' });
    }

    const updatedUser = await User.findByIdAndUpdate(
       {_id:editedData._id} ,
        { $set: editedData },
        { new: true, runValidators: true } 
    );

    if (!updatedUser) {
        return res.status(404).json({ message: 'User not found' });
    }

    res.status(200).json({ message: 'User updated successfully', user: updatedUser });
} catch (error) {
    res.status(500).json({ message: 'Server error', error: error.message });
}
})

app.delete('/deleteModel/:id',async (req,res)=>{
  const id = req.params.id;
  const editedData={"status":true}
  const updatedUser = await User.findByIdAndUpdate(
    {_id:id} ,
     { $set: editedData },
     { new: true, runValidators: true } 
 );
 if (!updatedUser) {
  return res.status(404).json({ message: 'User not found' });
}

res.status(200).json({ message: 'User updated successfully', user: updatedUser });
})

// Start server
const PORT = process.env.PORT || 8000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
