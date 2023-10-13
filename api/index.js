const dotenv = require("dotenv");
dotenv.config();
const express = require("express");
const mongoose = require("mongoose");
const User = require("./models/User");
const Post = require("./models/Post");
const bcrypt = require("bcryptjs");
const app = express();
const jwt = require("jsonwebtoken");
const cookieParser = require("cookie-parser");
const fs = require("fs");
const cors = require("cors");
const { default: axios } = require("axios");
const morgan = require("morgan");
const path = require('path'); 

app.use(morgan('dev'));

const salt = bcrypt.genSaltSync(10);
const secret = process.env.SECRET;

app.use(express.static(path.join(__dirname, 'build')));

app.use(express.json());
app.use(cookieParser());

const PORT = process.env.PORT || 4000;
const uri = process.env.MONGO_URI;

mongoose
  .connect(uri)
  .then(() => console.log("connected to MongoDB"))
  .catch(() => console.error("unable to connect to mongodb"));



app.post("/api/register", async (req, res) => {
  const { username, password } = req.body;
  try {
    const userDoc = await User.create({
      username,
      password: bcrypt.hashSync(password, salt),
    });
    res.json(userDoc);
  } catch (e) {
    console.log(e);
    res.status(400).json(e);
  }
});

app.post("/api/login", async (req, res) => {
  const { username, password } = req.body;
  const userDoc = await User.findOne({ username });

  if (!userDoc) {
    return res.status(400).json("wrong credentials");
  }

  const passOk = bcrypt.compareSync(password, userDoc.password);
  if (passOk) {
    // logged in
    jwt.sign({ username, id: userDoc._id }, secret, {}, (err, token) => {
      if (err) throw err;
      res
        .cookie("token", token, {
          httpOnly: true,
          secure: true,
        })
        .json({
          id: userDoc._id,
          username,
        });
    });
  } else {
    res.status(400).json("wrong credentials");
  }
});

app.get("/api/profile", (req, res) => {
  const { token } = req.cookies;
  jwt.verify(token, secret, {}, (err, info) => {
    if (err) throw err;
    console.log(info);
    res.json(info);
  });
});

app.post("/api/logout", (req, res) => {
  res.cookie("token", "").json("ok");
});

app.post("/api/post", async (req, res) => {
  try {
    const { token } = req.cookies;

    jwt.verify(token, secret, {}, async (err, info) => {
      if (err) throw err;
      const { title, summary, content, file } = req.body;

      console.log("body", req.body);

      const postDoc = await Post.create({
        title,
        summary,
        content,
        cover: file,
        author: info.id,
      });

      res.status(201).json(postDoc);
    });
  } catch (e) {
    res.status(404).json({ error: e });
  }
});

app.put("/api/post", async (req, res) => {
  const { token } = req.cookies;

  jwt.verify(token, secret, {}, async (err, info) => {
    if (err) throw err;
    try {
      const { id, title, summary, content, file } = req.body;
      const postDoc = await Post.findById(id);

      const isAuthor =
        JSON.stringify(postDoc.author) === JSON.stringify(info.id);
      if (!isAuthor) {
        return res.status(400).json("you are not the author");
      }
      await postDoc.update({
        title,
        summary,
        content,
        cover: file,
      });

      res.status(204).json(postDoc);
    } catch (e) {
      res.status(404).json({ error: e });
    }
  });
});

app.get("/api/post", async (req, res) => {
  res.json(
    await Post.find()
      .populate("author", ["username"])
      .sort({ createdAt: -1 })
      .limit(20)
  );
});

app.get("/api/post/:id", async (req, res) => {
  const { id } = req.params;
  const postDoc = await Post.findById(id).populate("author", ["username"]);
  res.json(postDoc);
});

app.listen(PORT);
//
