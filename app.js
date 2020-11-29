const express = require('express');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const session = require('express-session');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const mqtt = require('mqtt');
// simple HTTP server using TCP sockets
var locations = {}; // current latitude, current longitude, destination latitude, destination longitude
var app = express();
var mqttClient = mqtt.connect('ws://localhost:9001')
const n_days = 30; // max age of session cookie
const salt = 10; // for bcrypt encryption
app.set('port', process.env.PORT || 1234);
app.use(express.static(__dirname + '/public'));
app.use(session({
    rolling: true,
    name: 'SESSIONCOOKIE',
    secret: 'nice homework!',
    resave: true, // have to do with saving session under various conditions
    saveUninitialized: true, // just leave them as is
    httpOnly: false,
    cookie: {
        maxAge: null // by default, session will be removed when the browser is closed
        // if remember me is selected, than the session
        // will stay for 30 days
    }
}));
app.use(bodyParser.json()); // to support JSON-encoded bodies
app.use(bodyParser.urlencoded({
    extended: true
})); // to support URL-encoded bodies
app.use(cookieParser());
mongoose.connect('mongodb://localhost:27017/maphw', {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

// we create a schema first 
const userSchema = new mongoose.Schema({
    fullName: {
        type: String,
        required: true
    },
    email: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    },
    SESSIONID: {
        type: String,
        required: true
    }, // if it does not exist, then we need to give user a session id
    visited: {
        type: Date,
        required: false
    },
    currentLocation: {
        type: [],
        required: false
    },
    destinationLocation: {
        type: [],
        required: false
    }
})

const userModel = mongoose.model('users', userSchema);

app.get('/', function (req, res) {
    // login page
    userModel.findOne({
        SESSIONID: req.session.id,
    }).then(function (user) {
        if (user) {
            // user was found, so login the user and give them a session id
            res.redirect('/map');
        } else {
            res.sendFile(__dirname + '/public/login_page.html');
        }
    });
})

app.post('/login', function (req, res) {
    // do login and give session id to user
    userModel.findOne({
        email: req.body.email
    }).then(function (user) {
        if (user) {
            // user was found, so login the user and give them a session id
            // authenticate password first by comparing the two passwords (after hasing)
            bcrypt.compare(req.body.password, user.password, function (err, isEqual) {
                if (isEqual) {
                    user.SESSIONID = req.session.id;
                    user.save();
                    if (req.body.rememberMe) {
                        req.session.cookie.expires = false;
                        req.session.cookie.maxAge = 1000 * 60 * 60 * 24 * n_days; // Cookie will expire in 30 days
                        // and will not be removed if browser is closed
                    }
                    req.session.gdpr = req.body.gdpr;
                    res.status('200').send('OK'); // redirecting to the map page is done in the mqttClient side
                    // so that the user can see if their email/password was wrong
                    // without going to a new page
                } else {
                    res.status(400).send('Incorrect email or password.');
                }
            });
        } else {
            res.status(400).send('<html><h1>A user with this email does not exist! Please register an account on the register page (This can be found by clicking the "Create an account" on the bottom of the page</h1></html>')
        } // user was not found in the database, so send error
    });
});

app.get('/register', function (req, res) {
    // register page
    userModel.findOne({
        SESSIONID: req.session.id,
    }).then(function (user) {
        if (user) {
            // user was found, so login the user and give them a session id
            res.redirect('/map');
        } else {
            res.sendFile(__dirname + '/public/register_page.html');
        }
    });
    
})

app.post('/register', function (req, res) {
    // do registration and add user to MongoDB
    userModel.findOne({
        email: req.body.email
    }).then(function (user) {
        if (user) {
            res.status(400).send('<html><h1>A user with this email already exists! Please login or register again with a different email.</h1></html>')
        }
        // user was not found in the database, so register the user
        bcrypt.hash(req.body.password, salt, function (err, hash) {
            // encrypting the password
            registerUser = new userModel({
                fullName: req.body.fullName,
                email: req.body.email,
                password: hash,
                SESSIONID: req.session.id,
            });
            req.session.gdpr = req.body.gdpr;
            registerUser.save(function (err) {
                if (err) {
                    return res.status(403).send(err);
                } else  {
                    res.redirect('/map');
                }
            });
        });
    })
})

app.get('/map', function (req, res) {
    // map page, make sure user is logged in
    userModel.findOne({
        SESSIONID: req.session.id,
    }).then(function (user) {
        if (user) {
            // user was found with the correct session id, so serve them the map
            if(req.session.gdpr) {
                if (user.visited) {
                    res.cookie('lastVisited', user.visited);
                }
                res.cookie('name', user.fullName);
                res.cookie('email', user.email);
            }
            user.visited = Date.now();
            user.save();
            res.sendFile(__dirname + '/public/leaflet_test.html');
        } else {
            res.sendFile(__dirname + '/public/error_page.html');
        }
    });

})

app.get('/compass', function (req, res) {
    // map page, make sure user is logged in
    userModel.findOne({
        SESSIONID: req.session.id,
    }).then(function (user) {
        if (user) {
            res.sendFile(__dirname + '/public/compass.html');
        } else {
            res.sendFile(__dirname + '/public/error_page.html');
        }
    });

})

app.get('/logout', function (req, res) {
    // logout page to destroy the current session cookie and log the user out
    req.session.destroy();
    res.redirect('/');
})

app.get('/locations', function (req, res) {
    // respond with locations json, need to replace mqtt?
    res.sendFile(__dirname + '/public/leaflet_test.html');
})

app.post('/locations', function (req, res) {
    // updates locations, need to replace mqtt?
    res.sendFile(__dirname + '/public/leaflet_test.html');
})

// Need to subscribe to map to get location
// MQTT Client connection
mqttClient.on('connect', function () {
    // subscribing to topic to get the coordinates
    mqttClient.subscribe('map/coordinates', function (err) {
        if (!err) {
            console.log('Subscribed to coordinates topic');
        }
        else {
            console.log(err);
        }
    })
})

mqttClient.on('message', function (topic, message) {
    if (topic == 'map/coordinates') {
        // make sure the topic is correct
        var coordinatesString = message.toString();
        var parsedMessage = coordinatesString.split(' '); // current lat., current long., dest. lat., dest. long.
        const currentLocation = [parseFloat(parsedMessage[0]), parseFloat(parsedMessage[1])];
        const destinationLocation = [parseFloat(parsedMessage[2]), parseFloat(parsedMessage[3])];
        const email = parsedMessage[4];
        userModel.findOne({
            email: email
        }).then(function (user) {
            if (user) {
                user.currentLocation = currentLocation;
                user.destinationLocation = destinationLocation
                user.save();
            }
        })
    }
})

app.listen(app.get('port'), function () {
    console.log('Express started on http://localhost:' + app.get('port') + '; press Ctrl-C to terminate.');
})