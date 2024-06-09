const express = require('express');
const request = require('request');
const bodyParser = require('body-parser');
const path = require('path');
const cors = require('cors');
const ejs = require('ejs');
const { Pool } = require('pg');
const session = require('express-session');
const pgSession = require('connect-pg-simple')(session);
const mysql = require('mysql');
const axios = require('axios');
const bcrypt = require('bcrypt');
const multer = require('multer');
const app = express();
require('dotenv').config();
const fs = require('fs');
const port = 3000;
// const upload = multer({ dest: 'uploads/' });

app.use(cors());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'public')));
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'public')));
const upload = multer({ dest: __dirname + '/uploads/' });
app.use('/uploads', express.static('/'));

const pool = new Pool({
  user: process.env.DB_USER,
  host: process.env.DB_HOST,
  password: process.env.DB_PASSWORD,
  port: process.env.DB_PORT,
  database: process.env.DB_NAME
});

// Set up session middleware
app.use(session({
  store: new pgSession({
    pool: pool,
    tableName: 'session',
  }),
  secret: 'sqT_d_qxWqHyXS6Yk7Me8APygz3EjFE8',
  resave: false,
  saveUninitialized: true,
  cookie: {
    maxAge: 30 * 24 * 60 * 60 * 1000, // 30 days
  },
}));

const checkSession = (req, res, next) => {
  if (req.session.user) {
    next(); // Continue to the next middleware or route
  } else {
    res.redirect('/admin'); // Redirect to the login page if no session is found
  }
};

const saltRounds = 10;

app.post('/admin-registration', async (req, res) => {
  const { adminName, adminPhone, signupEmail, organisationName, adminRole, signupPassword } = req.body;

  try {
    // Hash the password
    const hashedPassword = await bcrypt.hash(signupPassword, saltRounds);


    await pool.query(`INSERT INTO admin (name, phone, email, organisation, role, pasword) VALUES ($1, $2, $3, $4, $5, $6)`,
      [adminName, adminPhone, signupEmail, organisationName, adminRole, hashedPassword]);

    res.status(200).json({ message: 'Admin registration successful' });
  } catch (error) {
    console.error('Error:', error.message);
    res.status(500).json({ error: 'An error occurred during registration' });
  }
});

app.post('/admin-login', async (req, res) => {
  const { loginEmail, loginPassword } = req.body;

  try {
    const result = await pool.query('SELECT * FROM admin WHERE email = $1', [loginEmail]);

    if (result.rows.length > 0) {
      const user = result.rows[0];
      const isPasswordMatch = await bcrypt.compare(loginPassword, user.pasword);

      if (isPasswordMatch) {
        req.session.user = user;

        // Check user role
        if (user.role === 'supervisor') {
          // Redirect supervisor to supervisor-verification route
          console.log(user.role)
          res.status(200).json({ success: true, message: 'Supervisor login successful', redirectTo: '/supervisor-verification' });
        } else {
          // Redirect admin to admin-panel route
          res.status(200).json({ success: true, message: 'Admin login successful', redirectTo: '/admin-panel' });
        }
      } else {
        res.status(401).json({ success: false, error: 'Invalid credentials' });
      }
    } else {
      res.status(401).json({ success: false, error: 'Invalid credentials' });
    }
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ success: false, error: 'Login failed' });
  }
});

app.get('/admin-dashboard', checkSession, async (req, res) => {
  try {
    // Retrieve user ID from session
    const userId = req.session.user.id; // Assuming user ID is stored in session
    const orgCode = req.session.user.org_code;
    // Query to fetch user information based on user ID
    const query = 'SELECT name, phone, email, organisation, unique_code, org_code FROM admin WHERE id = $1';
    const result = await pool.query(query, [userId]);

    // If user not found
    if (result.rows.length === 0) {
      // return res.status(404).json({ error: 'User not found' });
    }

    // Extract user information from the result
    const { name, phone, email, organisation, unique_code, org_code } = result.rows[0];

    // Query to fetch supervisors from admin table
    const supervisorQuery = `
SELECT * 
FROM admin 
WHERE org_code = $1 
AND role = 'supervisor'
`;
    const supervisorResult = await pool.query(supervisorQuery, [orgCode]);
    const supervisors = supervisorResult.rows;

    // Loop through each supervisor to fetch corresponding users and participants
    for (let i = 0; i < supervisors.length; i++) {
      const supervisor = supervisors[i];

      // Query to fetch users for each supervisor
      const usersQuery = `
  SELECT * 
  FROM users 
  WHERE unique_code = $1
`;
      const usersResult = await pool.query(usersQuery, [supervisor.unique_code]);
      const users = usersResult.rows;

      // Loop through each user to fetch corresponding participants
      for (let j = 0; j < users.length; j++) {
        const user = users[j];

        // Query to fetch participants for each user
        const participantQuery = `
    SELECT * 
    FROM participants 
    WHERE user_id = $1
  `;
        const participantResult = await pool.query(participantQuery, [user.id]);
        user.participants = participantResult.rows;
      }

      // Assign users to supervisor
      supervisor.users = users;
    }

    // console.log(supervisors);

    // Render the admin-panel template and pass user information to it
    res.render('admin-panel', { name, phone, email, organisation, unique_code, org_code, supervisors });
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/', async (req, res) => {
  res.render('index');
});

app.get('/help', async (req, res) => {
  res.render('help');
});

app.get('/user-registration', async (req, res)=>{
  res.render('user-registration');
});

app.get('/login', async (req, res) => {
  res.render('user-login');
});

app.get('/organisation', checkSession, async (req, res) => {
  res.render('organisation-verification');
});

app.get('/admin', async (req, res) => {
  res.render('admin-login');
});

app.get('/admin-registration', async (req, res) => {
  res.render('admin-registration');
});

app.get('/supervisor-verification', checkSession, async (req, res) => {
  res.render('supervisor-verification');
});

// Route for verifying organization code
app.post('/supervisor-verification', checkSession, async (req, res) => {
  const { code } = req.body; // Assuming you're passing the code in the request body

  try {
    const userId = req.session.user.id;
    // Check if the provided code exists in the admin table
    const adminQuery = `
          SELECT *
          FROM admin
          WHERE org_code = $1;
      `;

    const adminResult = await pool.query(adminQuery, [code]);

    if (adminResult.rows.length > 0) {
      // Code exists in the admin table, update the org_code field of the logged-in user
      const updateQuery = `
              UPDATE admin
              SET org_code = $1
              WHERE id = $2;
          `;

      await pool.query(updateQuery, [code, userId]);

      res.status(200).json({ message: 'Verification successful' });
    } else {
      // Code does not exist in the admin table
      res.status(400).json({ error: 'Verification failed' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/supervisor-panel', checkSession, async (req, res) => {
  try {
    // Retrieve user information from session
    const sessionUser = req.session.user;

    // Extract user ID and unique code
    const userId = sessionUser.id;
    const uniqueCode = sessionUser.unique_code;

    // console.log(userId, uniqueCode)

    // Query to fetch user information based on user ID
    const userQuery = 'SELECT name, phone, email, organisation, unique_code, org_code FROM admin WHERE id = $1';
    const userResult = await pool.query(userQuery, [userId]);

    // If user not found
    if (userResult.rows.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    // Extract user information from the result
    const { name, phone, email, organisation, unique_code, org_code } = userResult.rows[0];

    // Query to fetch users with matching unique_code
    const usersQuery = 'SELECT * FROM users WHERE unique_code = $1';
    const usersResult = await pool.query(usersQuery, [uniqueCode]);
    const matchedUsers = usersResult.rows;

    // Query to fetch participants for each user
    for (let i = 0; i < matchedUsers.length; i++) {
      const user = matchedUsers[i];
      const participantQuery = 'SELECT * FROM participants WHERE user_id = $1';
      const participantResult = await pool.query(participantQuery, [user.id]);
      user.participants = participantResult.rows;
    }

    // Render the supervisor-panel template and pass user information and matched users to it
    res.render('supervisor-panel', { name, phone, email, organisation, unique_code, org_code, matchedUsers });
  } catch (error) {
    console.error('Error fetching user data:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

// Sample route for user registration
app.post('/user-registration', async (req, res) => {
  const { researcherName, signupEmail, signupPhone, signupPassword } = req.body;

  try {
    // Insert the user data into the users table
    const hashedPassword = await bcrypt.hash(signupPassword, saltRounds);
    const query = `
          INSERT INTO users (name, email, phone, password)
          VALUES ($1, $2, $3, $4);
      `;

    await pool.query(query, [researcherName, signupEmail, signupPhone, hashedPassword]);

    res.status(200).json({ message: 'User registered successfully' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.post('/user-login', async (req, res) => {
  const { loginEmail, loginPassword, location } = req.body;

  try {
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [loginEmail]);

    if (result.rows.length > 0) {
      const user = result.rows[0];
      const isPasswordMatch = await bcrypt.compare(loginPassword, user.password);

      if (isPasswordMatch) {
        // Update last_login_time with current timestamp
        const currentDate = new Date().toISOString();

        // Update user's location
        await pool.query('UPDATE users SET last_login_time = $1, location = $2 WHERE email = $3', [currentDate, location, loginEmail]);

        req.session.user = user;
        res.status(200).json({ success: true, message: 'Login successful' });
      } else {
        res.status(401).json({ success: false, error: 'Invalid credentials' });
      }
    } else {
      res.status(401).json({ success: false, error: 'Invalid credentials' });
    }
  } catch (error) {
    console.error('Error during login:', error);
    res.status(500).json({ success: false, error: 'Login failed' });
  }
});

app.post('/organization-verification', checkSession, async (req, res) => {
  const { code } = req.body; // Assuming you're passing the code in the request body

  try {
    const userId = req.session.user.id;
    // Check if the provided code exists in the admin table
    const adminQuery = `
          SELECT *
          FROM admin
          WHERE unique_code = $1;
      `;

    const adminResult = await pool.query(adminQuery, [code]);

    if (adminResult.rows.length > 0) {
      // Code exists in the admin table, update the org_code field of the logged-in user
      const updateQuery = `
              UPDATE users
              SET unique_code = $1
              WHERE id = $2;
          `;

      await pool.query(updateQuery, [code, userId]);

      res.status(200).json({ message: 'Verification successful' });
    } else {
      // Code does not exist in the admin table
      res.status(400).json({ error: 'Verification failed' });
    }
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

app.get('/home', checkSession, async (req, res) => {
  const userId = req.session.user.id;
  // const organisationCode = res.session.user.unique_code;

  try {
    const client = await pool.connect();
    const result = await client.query('SELECT * FROM participants WHERE user_id = $1', [userId]);
    const participants = result.rows;
    client.release();

    // Check if participants data is empty
    if (participants.length === 0) {
      // If no participants found, return a 404 Not Found response
      // return res.status(404).send('No participants found');
      // console.log(participants);
    }

    // If participants found, render the 'home' template and pass the data
    res.render('home', { userId: userId, participants: participants });
  } catch (err) {
    console.error('Error executing query', err);
    // If an error occurs during the query execution, return a 500 Internal Server Error response
    res.status(500).send('No participants');
  }
});

// Route to add participant
// Route to add participant
app.post('/add-participant', upload.single('picture'), async (req, res) => {
  try {
    const { name, phone, email, userId } = req.body;

    // Log the uploaded file object
    // console.log(req.file);

    // Ensure that req.file contains the expected file information
    if (!req.file || !req.file.path) {
      return res.status(400).json({ message: 'No picture uploaded' });
    }

    // Use req.file.path or other relevant property to get the file path
    const picturePath = req.file.path;
    // console.log(picturePath);

    // Insert participant data into PostgreSQL with the file path
    const query = 'INSERT INTO participants (name, phone, email, picture_data, user_id) VALUES ($1, $2, $3, $4, $5)';
    const values = [name, phone, email, picturePath, userId];
    await pool.query(query, values);

    res.status(201).json({ message: 'Participant added successfully' });
  } catch (error) {
    console.error('Error adding participant:', error);
    res.status(500).json({ message: 'Failed to add participant. Please try again.' });
  }
});

app.post('/help', async (req, res) => {
  const { email, phone, problem } = req.body;
  try {
      // Insert form data into the 'help' table
      const query = 'INSERT INTO help (email, phone, problem) VALUES ($1, $2, $3)';
      await pool.query(query, [email, phone, problem]);

      // Send success response to frontend
      res.status(200).json({ success: true, message: 'Form submitted successfully' });
  } catch (error) {
      console.error('Error submitting form:', error);
      res.status(500).json({ success: false, error: 'Failed to submit form' });
  }
});

app.listen(port, () => {
  console.log(`Server listening on port ${port}`)
});