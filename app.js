const express =     require('express');
const session =     require('express-session');
const MongoStore =  require('connect-mongo');
const bcrypt =      require('bcrypt');

require('dotenv').config();
const Joi = require('joi');


const app = express();                  // Create an instance of express
const port = process.env.PORT || 3000;  // Set the view engine to ejs

const saltRounds = 12;                  // Number of rounds for bcrypt hashing
const expireTime = 1000 * 60 * 60       // 1 hour
const node_session_secret = process.env.NODE_SESSION_SECRET; // Use environment variable for session secret

const mongodb_user = process.env.MONGODB_USER; // Use environment variable for username
const mongodb_password = process.env.MONGODB_PASSWORD; // Use environment variable for password


// --MIDDLEWARE--
// Middleware to parse JSON bodies
app.use(express.urlencoded({extended: false}));

app.use(express.static('public'));

// Create a new MongoDB store instance
var mongoStore = MongoStore.create({ 
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${process.env.MONGODB_HOST}/${process.env.MONGODB_DATABASE}`,
})

// Middleware to serve static files from the 'public' directory
app.use(session({
    secret:             node_session_secret,
    store:              mongoStore,
    saveUninitialized:  false,
    resave:             true
}));

const { MongoClient } = require('mongodb');

const uri = `mongodb+srv://${mongodb_user}:${mongodb_password}@${process.env.MONGODB_HOST}/`;
const client = new MongoClient(uri);
let usersCollection;

const loginSchema = Joi.object({
    email: Joi.string().email().required(),
    password: Joi.string().min(6).required()
  });


async function connectToMongo() 
{
  try 
  {
    await client.connect();
    const db = client.db(`${process.env.MONGODB_DATABASE}`); 
    usersCollection = db.collection("users"); // store users here
    console.log("Connected to MongoDB Atlas");
  } 
  catch (err) 
  {
    console.error("MongoDB connection error:", err);
  }
}

connectToMongo();

// --ROUTES--
// Home Page
app.get('/', (req, res) =>
{
    if(!req.session.authenticated)
    {
        res.send(`
            <h1> 
                Welcome to Home Page 
            </h1>
            <a href = "/signup"><button>Sign Up</button></a>
            <br>
            <a href = "/login"><button>Login</button></a>
            <br>
        `);
    }
    else
    {
        var html = `
            <h1>
                Hello, ${req.session.username}!
            </h1>
            <a href = "/members"><button>Go To Members Area!</button></a>
            <br>
            <a href = "/logout"><button>Log Out</button></a>
            <br>
            `;

        res.send(html);
    }

});

// Sign Up Page
app.get('/signup', (req, res) =>
{
    // Check if there are any missing fields in the query string
    var missingFields = req.query.missingFields;

    var html =`
        <h1> 
            Welcome to Sign Up Page 
        </h1>

        <p>Create User</p>

        <form action='/createUser' method='post'>
            <input type='text' name='username' placeholder='Username' required>
            <br>
            <input type='email' name='email' placeholder='Email' required>
            <br>
            <input type='password' name='password' placeholder='Password' required>
            <br>
            <button type='submit'>Sign Up</button>
        </form>
    `;

    // If there are missing fields, add a message to the HTML
    if(missingFields)
        {
            html += "<br><p style='color: red;'>Please fill in all fields!</p>";
        }

    res.send(html);
});

// Create User
app.post('/createUser', async (req, res) =>
{
    var username =  req.body.username;
    var email =     req.body.email;
    var password =  req.body.password;

    // Check if any of the fields are empty, if so redirect to signup page with a query parameter
    if(!email || !password || !username)
    {
        res.redirect('/signup?missingFields=1');
        return;
    }

    var hashedPassword = bcrypt.hashSync(password, saltRounds); // Hash the password

    try {
        await usersCollection.insertOne({ username, email, password: hashedPassword });
        res.redirect('/login');
      } catch (err) {
        console.error("Error saving user:", err);
        res.send("Error creating user.");
      }

});

// Login Page
app.get('/login', (req, res) =>
{
    var html = `
        <h1> 
            Welcome to Login Page 
        </h1>
        <form action = '/loginUser' method = 'post'>
            <input type = 'email' name = 'email' placeholder = 'Email' required>
            <br>
            <input type = 'password' name = 'password' placeholder = 'Password' required>
            <br>
            <button type = 'submit'>Login</button>
        </form>
    `;
    res.send(html);
});

// Login User
app.post('/loginUser', async (req, res) =>
{
    var email = req.body.email;
    var password = req.body.password;

    const { error } = loginSchema.validate({ email, password});
    if (error) {
        return res.status(400).send('Invalid login input');
      }

    const user = await usersCollection.findOne({ email });

  if (user && bcrypt.compareSync(password, user.password)) {
    req.session.authenticated = true;
    req.session.email = email;
    req.session.username = user.username;
    req.session.cookie.maxAge = expireTime;
    return res.redirect('/');
  }

  res.redirect('/login');
});

// Members Page
app.get('/members', (req, res) =>
{
    if (!req.session.authenticated) 
    {
        return res.redirect('/');
    }

    const images = [
        'meme1.jpg', 
        'meme2.jpg',
        'meme3.jpg'
    ];

    const randomImage = images[Math.floor(Math.random() * images.length)];

    res.send(`
        <h1> 
             Hello, ${req.session.username}! 
        </h1>
        <img src="/${randomImage}" alt="Random Image" />
        <br>
        <a href="/logout"><button>Log Out</button></a>
        `);
});

// Logout Page
app.get('/logout', (req, res) =>
{
    req.session.destroy(err => 
        {
        if (err) 
            {
            console.error("Error destroying session:", err);
            return res.send("Error logging out.");
        }

        // Clear session cookie
        res.clearCookie('connect.sid');

        // Redirect to home page or login
        res.redirect('/');
    });
});  

// 404 Page Not Found
app.get('*', (req, res) =>
{
    res.status(404);

    res.send(`
        <h1> 
            404 - Page Not Found
        </h1>
        <a href = "/"><button>Return Home</button></a>
        `);
});


// --SERVER--
// Start the Server
app.listen(port, () => 
{
    console.log(`Server is running on http://localhost: ${port}`);
});