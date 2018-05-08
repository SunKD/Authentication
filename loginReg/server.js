// Require the Express Module
var express = require('express');
// Create an Express App
var app = express();
var session = require('express-session');
const flash = require('express-flash');
const bcrypt = require('bcrypt');
const saltRounds = 10;
var mongoose = require('mongoose');
mongoose.connect('mongodb://localhost/loginReg');
var UserSchema = new mongoose.Schema({
    email: {
        type: String,
        trim: true,
        lowercase: true,
        unique: true,
        required: 'Email address is required',
        validate: [validateEmail, 'Please fill a valid email address'],
        match: [/^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/, 'Please fill a valid email address']
    },
    first_name: {
        type: String,
        required: 'First name is required, Minimum length is 2',
        minlength: 2
    },
    last_name: {
        type: String,
        required: 'Last name is required, Minimum length is 2',
        minlength: 2
    },
    password: {
        type: String,
        required: true,
        minlength: 3
    },
    birthday: {
        type: Date,
        required: 'Please provide your birthday',
    }
}, { timestamps: true });
mongoose.model('User', UserSchema); // We are setting this Schema in our Models as 'Quote'
var User = mongoose.model('User')
// Require body-parser (to receive post data from clients)
var bodyParser = require('body-parser');
// Integrate body-parser with our App
app.use(bodyParser.urlencoded({ extended: true }));
// Require path
var path = require('path');
var hashedPW;

app.use(session({
    secret: 'somesuperdupersecret',
    resave: true,
    saveUninitialized: true
}))
app.use(flash());
// Setting our Static Folder Directory
app.use(express.static(path.join(__dirname, './static')));
// Setting our Views Folder Directory
app.set('views', path.join(__dirname, './views'));
// Setting our View Engine set to EJS
app.set('view engine', 'ejs');
// Routes
// Root Request
app.get('/', function (req, res) {
    User.find({}, function (err, users) {
        console.log(users);
    })
    return res.render('index');
})

app.post('/register', function (req, res) {
    if (req.body.password != req.body.confirmPW) {
        var errors = "Password does not match";
        req.flash('registration', errors);
        return res.redirect('/');
    }

    bcrypt.genSalt(saltRounds, function (err, salt) {
        bcrypt.hash(req.body.password, salt, function (err, hash) {
            console.log(hash + "hased password")
            hashedPW = hash;
            var newUser = new User({
                email: req.body.email,
                first_name: req.body.first_name,
                last_name: req.body.last_name,
                birthday: req.body.birthday,
                password: hashedPW
            });
            newUser.save(function (err) {
                if (err) {
                    console.log("We have an error!", err);
                    for (var key in err.errors) {
                        req.flash('registration', err.errors[key].message);
                    }
                    return res.redirect('/');
                }
            })
        });
    });
    return res.redirect('/loggedin');
})

app.get('/loggedin', function (req, res) {
    return res.render('loggedin');
})

app.post('/login', function (req, res) {
    var authenticated = false;
    User.findOne({ email: req.body.loginemail }, function (err, user) {
        if (user == null) {
            var error = "Email doesn't exist. Please register";
            req.flash('registration', error);
            return res.redirect('/');
        } else {
            bcrypt.compare(req.body.loginpw, user.password, function (err, result) {
                if (result) {
                    authenticated = true;
                    attemptLogin(authenticated, req, res);

                }else{
                    attemptLogin(authenticated, req, res);
                }
            });
        }
    })
})

// app.post('/login', (req, res) => {
//     User.findOne({email:req.body.loginemail}, (err, user) => {
//         if (user == null) {
//             //error message here
//             return res.redirect('/');
//         }
//         else if (user){
//             bcrypt.compare(req.body.loginpw, user.password)
//             .then( truth => {
//                 //setting logged in user
//                 req.session.user_id = user._id;
//                 return res.redirect('/loggedin');
//             })
//             .catch( err => {
//                 req.flash('loginMessage', 'Invalid Login Credentials.')
//                 return res.redirect('/');
//             })
//         }
//     })
// })

function validateEmail(email) {
    var re = /^(([^<>()\[\]\\.,;:\s@"]+(\.[^<>()\[\]\\.,;:\s@"]+)*)|(".+"))@((\[[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/;
    return re.test(String(email).toLowerCase());
}

function attemptLogin(authenticated, req, res){
    if (authenticated) {
        return res.redirect('/loggedin')
    } else {
        var err = "Password is not matching."
        req.flash('registration', err);
        return res.redirect('/');
    }
}

// Setting our Server to Listen on Port: 8000
app.listen(8000, function () {
    console.log("listening on port 8000");
})