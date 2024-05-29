const express = require("express");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const admin = require("firebase-admin");
const ejs = require("ejs");

admin.initializeApp({
  credential: admin.credential.cert({
    type: "service_account",
    projectId: process.env.FIREBASE_PROJECT_ID,
    privateKeyId: process.env.FIREBASE_PRIVATE_KEY_ID,
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n"),
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    clientId: process.env.FIREBASE_CLIENT_ID,
    authUri: process.env.FIREBASE_AUTH_URI,
    tokenUri: process.env.FIREBASE_TOKEN_URI,
    authProviderX509CertUrl: process.env.FIREBASE_AUTH_PROVIDER_X509_CERT_URL,
    clientX509CertUrl: process.env.FIREBASE_CLIENT_X509_CERT_URL,
  }),
  databaseURL: process.env.FIREBASE_DATABASE_URL,
});

const app = express();
app.use(express.json());

// Page for dummy login
app.set("view engine", "ejs");
app.engine("html", ejs.renderFile);
app.use(express.static("static"));
app.get("/dummy/login", (req, res) => {
  res.render("./dummy-login.html", {
    apiKey: process.env.FIREBASE_CLIENT_API_KEY,
    authDomain: process.env.FIREBASE_CLIENT_AUTH_DOMAIN,
    projectID: process.env.FIREBASE_CLIENT_PROJECT_ID,
    storageBucket: process.env.FIREBASE_CLIENT_STORAGE_BUCKET,
    messagingSenderID: process.env.FIREBASE_CLIENT_MESSAGING_SENDER_ID,
    appID: process.env.FIREBASE_CLIENT_APP_ID,
  });
});

const { Book, User } = require("./models");

app.get("/", (req, res) => {
  res.send({ message: "Hello World!" });
});

app.post("/users/register", async (req, res) => {
  const { name, email, password } = req.body;
  const isUserExist = await User.findOne({ where: { email } });
  if (isUserExist) {
    return res.status(400).send({ message: "Email already registered" });
  }

  const hashedPassword = await bcrypt.hash(password, 10);
  const user = await User.create({ name, email, password: hashedPassword });

  user.password = undefined;

  res.send(user);
});

app.post("/users/login", async (req, res) => {
  const { email, password } = req.body;

  const user = await User.findOne({ where: { email } });
  if (!user) {
    return res.status(400).send({ message: "Email not registered" });
  }

  if (user.isGoogleLogin) {
    return res.status(400).send({ message: "Please login with Google" });
  }

  const isValidPassword = await bcrypt.compare(password, user.password);
  if (!isValidPassword) {
    return res.status(400).send({ message: "Invalid password" });
  }

  const token = jwt.sign(
    {
      id: user.id,
      email: user.email,
      name: user.name,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: 24 * 60 * 60,
    }
  );

  user.password = undefined;

  const response = { user, token };
  res.send(response);
});

app.post("/users/login-google", async (req, res) => {
  const { idToken } = req.body;
  const decodedToken = await admin.auth().verifyIdToken(idToken);
  const { email, name } = decodedToken;

  if (decodedToken.email_verified === false) {
    return res.status(400).send({ message: "Email not verified" });
  }

  let user = await User.findOne({ where: { email } });
  if (!user) {
    user = await User.create({ name, email, isGoogleLogin: true });
  }

  const token = jwt.sign(
    {
      id: user.id,
      email: user.email,
      name: user.name,
    },
    process.env.JWT_SECRET,
    {
      expiresIn: 24 * 60 * 60,
    }
  );

  user.password = undefined;

  const response = { user, token };
  res.send(response);
});

const verifyToken = (req, res, next) => {
  let token = req.header("Authorization");
  if (!token) {
    return res.status(401).send({ message: "Access denied" });
  }

  token = token.replace("Bearer ", "");

  try {
    const verified = jwt.verify(token, process.env.JWT_SECRET);
    req.user = verified;
    next();
  } catch (err) {
    res.status(400).send({ message: "Invalid token" });
  }
};

app.get("/books", verifyToken, async (req, res) => {
  console.log(process.env.DB_NAME);
  console.log(process.env.JWT_SECRET);
  const books = await Book.findAll();
  res.send(books);
});

app.post("/books", async (req, res) => {
  const { title, author } = req.body;
  const book = await Book.create({ title, author });
  res.send(book);
});

app.get("/books/:id", async (req, res) => {
  const { id } = req.params;
  const book = await Book.findByPk(id);
  if (!book) {
    return res.status(404).send({ message: "Book not found" });
  }
  res.send(book);
});

app.put("/books/:id", async (req, res) => {
  const { id } = req.params;
  const { title, author } = req.body;
  const book = await Book.findByPk(id);
  if (!book) {
    return res.status(404).send({ message: "Book not found" });
  }

  book.title = title;
  book.author = author;

  await book.save();

  res.send(book);
});

app.delete("/books/:id", async (req, res) => {
  const { id } = req.params;
  const book = await Book.findByPk(id);
  if (!book) {
    return res.status(404).send({ message: "Book not found" });
  }

  await book.destroy();

  res.send({ message: "Book deleted" });
});

app.listen(3000, () => {
  console.log("Server is running on port 3000");
});
