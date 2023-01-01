require('dotenv').config();
const express = require("express");
const bodyParser = require("body-parser");
const mongoose = require( "mongoose");
const session = require( "express-session");
const passport = require('passport');
const passportLocalMongoose = require('passport-local-mongoose');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const findOrCreate = require('mongoose-findorcreate');
const app = express();

app.set('view engine', 'ejs');
app.use(bodyParser.urlencoded({extended:true}));
app.use(express.static('public'));

app.use(session({
    secret: process.env.SECRET,
    resave: false,
    saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

mongoose.set('strictQuery', false);
mongoose.connect('mongodb://localhost:27017/userDB'); 

const userSchema = new mongoose.Schema({
    email: String,
    password: String,
    googleId: String,
    secrets: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const User = mongoose.model('user', userSchema);

passport.use(User.createStrategy());
passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser((id, done) => {
    User.findById(id, (err, user) => {
        done(err, user);
    })
});

// Google Authentication /////////////////////////////////////////
passport.use(new GoogleStrategy({
    clientID: process.env.CLIENT_ID,
    clientSecret: process.env.CLIENT_SECRET,
    callbackURL: "http://localhost:3000/auth/google/secrets",
    userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
  },
  function(accessToken, refreshToken, profile, cb) {
    console.log(profile);
    User.findOrCreate({ googleId: profile.id }, function (err, user) {
      return cb(err, user);
    });
  }
));

// Home Route //////////////////////////////////
app.get('/', (req, res) => {
    res.render('home')
 });

 app.get('/secrets', (req, res) => {
        User.find({"secrets": {$ne: null}}, (err, foundUsers) => {
            if(err){
                console.log(err)
            } else {
                if(foundUsers){
                    console.log(foundUsers)
                    res.render("secrets", {usersSecrets: foundUsers});
                }
            }
        });
       
});

app.get('/submit', (req, res) => {
    if(req.isAuthenticated){
        res.render('submit')
    } else {
        res.redirect('/login')
    }  
});

app.post('/submit', (req, res) => {
    const submittedSecret = req.body.secret;

    console.log(req.user.id)
    User.findById(req.user.id, (err, foundUser) => {
        if(err){
            console.log(err);
        } else {
            if(foundUser){
                foundUser.secrets = submittedSecret;
                foundUser.save(() => {
                        res.redirect('/secrets');
                });
            }
        }
    })
})

app.get('/auth/google', 
    passport.authenticate('google', {scope: [ 'profile' ]})
)

app.get('/auth/google/secrets', 
  passport.authenticate('google', { failureRedirect: '/login' }),
  function(req, res) {
    res.redirect('/secrets');
  });

// Register Route //////////////////////////////////////////////////////////

 app.route('/register')

.get(
    (req, res) => { 
        res.render('register')
    }
)

.post(
    (req, res) => {
        User.register({username: req.body.username}, req.body.password, (err, user) => {
            if(err){
                console.log(err);
                res.redirect('/register')
            } else {
                passport.authenticate('local')(req, res, () => {
                    res.redirect('/secrets')
                })
            }
        })
    }
);

//Login Route //////////////////////////////////////////////////////////////

app.route('/login')

 .get(
    (req, res) => {
        res.render('login')
     }
 )

 .post(
    (req, res) => {
        const user = new User({
         username: req.body.username,
         password: req.body.password
        });

        req.login(user, (err) => {
            if(err){
                console.log(err);
                res.send(err);
            } else {
                passport.authenticate('local')(req, res, () => {
                    res.redirect('/secrets')
                })
            }
        })
    }
);

//Logout Route ///////////////////////////////////////////////////////

app.get('/logout', (req, res) => {
    req.logout((err) => {
        if(err){
            console.log(err)
        } else {
            res.redirect('/');
        }
    });
    
});

let port = process.env.PORT || 3000;

app.listen(port, () => {
    console.log('Server has Started Sucessfully')
});