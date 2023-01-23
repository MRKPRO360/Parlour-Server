const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const express = require("express");
const cors = require("cors");
require("dotenv").config();
const jwt = require("jsonwebtoken");
const stripe = require("stripe")(process.env.STRIPE_SECRET);

const app = express();
app.use(express.json());
app.use(cors());

const port = process.env.PORT || 5000;

const uri = `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASSWORD}@cluster0.8v0lano.mongodb.net/?retryWrites=true&w=majority`;
const client = new MongoClient(uri, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverApi: ServerApiVersion.v1,
});

// creating jwt token
app.post("/jwt", async (req, res) => {
  const user = req.body;
  const token = jwt.sign(user, process.env.ACCESS_TOKEN_SECRET, {
    expiresIn: "90d",
  });
  res.send({ token });
});

// verifying jwt user token

const verifyJWT = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader)
    return res.status(401).send({ message: "Unauthorized access" });
  const token = authHeader.split(" ")[1];

  jwt.verify(token, process.env.ACCESS_TOKEN_SECRET, (err, decoded) => {
    if (err) return res.status(403).send({ message: "Forbidden access" });

    req.decoded = decoded;
    next();
  });
};

// verify user midlleware
const verifyUser = async (req, res, next) => {
  const email = req.query.email;
  const decoded = req.decoded;

  if (decoded.email !== email)
    return res.status(403).send({ message: "Forbidden access" });
  next();
};

const run = async function () {
  try {
    const servicesCollection = client.db("parlour").collection("services");
    const bookingsCollection = client.db("parlour").collection("bookings");
    const usersCollection = client.db("parlour").collection("users");
    const paymentsCollection = client.db("parlour").collection("payments");

    // verify admin
    const verifyAdmin = async (req, res, next) => {
      const decodedEmail = req.decoded.email;
      const query = { email: decodedEmail };

      const user = await usersCollection.findOne(query);

      if (user?.role !== "admin")
        return res.status(403).send({ message: "Forbidden access" });

      next();
    };

    app.get("/services", async (req, res) => {
      const services = await servicesCollection.find({}).toArray();
      res.send(services);
    });

    app.post("/services", verifyJWT, verifyAdmin, async (req, res) => {
      const service = req.body;
      const result = await servicesCollection.insertOne(service);
      res.send(result);
    });

    // delete services only for admin
    app.delete("/services/:id", verifyJWT, verifyAdmin, async (req, res) => {
      const id = req.params.id;

      const query = { _id: ObjectId(id) };
      const result = await servicesCollection.deleteOne(query);
      res.send(result);
    });

    // get all bookings for admin

    app.get("/bookingsForAdmin", verifyJWT, verifyAdmin, async (req, res) => {
      const bookings = await bookingsCollection.find({}).toArray();
      res.send(bookings);
    });

    // get all bookings for specific user
    //need to verify user
    app.get("/bookings", verifyJWT, verifyUser, async (req, res) => {
      const query = {
        email: req.query.email,
      };

      const bookings = await bookingsCollection.find(query).toArray();
      res.send(bookings);
    });

    // get specific book by id
    app.get("/bookings/:id", verifyJWT, verifyUser, async (req, res) => {
      const id = req.params.id;
      const query = { _id: ObjectId(id) };

      const bookings = await bookingsCollection.findOne(query);
      res.send(bookings);
    });

    // delete a book
    app.delete("/bookings/:id", verifyJWT, verifyUser, async (req, res) => {
      const id = req.params.id;
      const query = { _id: ObjectId(id) };

      const result = await bookingsCollection.deleteOne(query);
      res.send(result);
    });

    // create a book
    app.post("/bookings", verifyJWT, async (req, res) => {
      const booking = req.body;
      const decoded = req.decoded;

      if (decoded.email !== req.body.email)
        return res.status(403).send({ message: "Forbidden access" });

      // verifying if the user already booked this item on same date
      const query = {
        email: req.body.email,
        serviceName: req.body.serviceName,
        bookedDate: req.body.bookedDate,
      };
      const alreadyBooked = await bookingsCollection.findOne(query);

      if (alreadyBooked)
        return res
          .status(404)
          .send({ message: "This service is already booked on this date" });

      const result = await bookingsCollection.insertOne(booking);
      res.send(result);
    });

    // check user if she/he is an admin
    app.get("/users/admin", async (req, res) => {
      const email = req.query.email;
      const query = { email: email };

      const user = await usersCollection.findOne(query);
      res.send({ isAdmin: user?.role === "admin" });
    });

    // create user
    app.post("/users", async (req, res) => {
      const user = req.body;

      // Check if the user is already in database
      const query = {
        name: req.body.name,
        email: req.body.email,
      };

      const alreadyLoggedIn = await usersCollection.findOne(query);

      if (alreadyLoggedIn)
        return res.send({ message: "user already logged in" });

      const result = await usersCollection.insertOne(user);

      res.send(result);
    });

    app.get("/users", verifyJWT, verifyAdmin, async (req, res) => {
      const customers = await usersCollection.find({}).toArray();
      res.send(customers);
    });

    // update user to admin
    // need to be varified first if she/he is a user (future)
    app.patch("/makeAdmin", verifyJWT, verifyAdmin, async (req, res) => {
      const email = req.body.email;

      const filter = { email: email };

      const updatedDoc = {
        $set: {
          role: "admin",
        },
      };
      const result = await usersCollection.updateOne(filter, updatedDoc);
      res.send(result);
    });

    // stripe payment-intent

    app.post(
      "/create-payment-intent",
      verifyJWT,
      verifyUser,
      async (req, res) => {
        const book = req.body;
        const price = book.price;

        const amount = price * 100;

        const paymentIntent = await stripe.paymentIntents.create({
          currency: "usd",
          amount: amount,
          payment_method_types: ["card"],
        });

        res.send({
          clientSecret: paymentIntent.client_secret,
        });
      }
    );

    app.post("/payments", verifyJWT, verifyUser, async (req, res) => {
      const payment = req.body;
      const result = await paymentsCollection.insertOne(payment);

      const id = payment.bookId;
      const filter = { _id: ObjectId(id) };

      const updatedDoc = {
        $set: {
          paid: true,
          transactionId: payment.transactionId,
        },
      };

      const updatedResult = await bookingsCollection.updateOne(
        filter,
        updatedDoc
      );
      res.send(result);
    });
  } finally {
  }
};

run().catch((err) => console.error(err));

app.get("/", (req, res) => {
  res.send("Hello from the server");
});

app.listen(port, () => {
  console.log(`App is running on port ${port}`);
});
