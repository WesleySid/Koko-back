const express = require("express");
const cors = require("cors");
const app = express();
const mongoose = require("mongoose");
const uid2 = require("uid2");
const SHA256 = require("crypto-js/sha256");
const encBase64 = require("crypto-js/enc-base64");
const User = require("./Models/User");

mongoose
  .connect("mongodb://localhost:27017/Yuka")
  .then(() => {
    console.log("Connexion à MongoDB établie avec succès !");
  })
  .catch((err) => {
    console.error("Erreur lors de la connexion à MongoDB :", err);
  });

app.use(express.json());
app.use(cors());

app.post("/signup", async (req, res) => {
  try {
    console.log("Requête POST reçue sur /signup", req.body);
    // Vérifier si toutes les informations requises sont fournies
    if (!req.body.username || !req.body.email || !req.body.password) {
      console.log("Informations manquantes dans la requête :", req.body);
      return res.status(400).json({
        message: "Nom d'utilisateur, email ou mot de passe manquant",
      });
    }
    // Vérifier si l'email est déjà utilisé
    const alreadyExist = await User.findOne({ email: req.body.email });
    if (alreadyExist) {
      console.log("Email déjà utilisé :", req.body.email);
      return res.status(400).json({ message: "Email déjà utilisé" });
    }

    const salt = uid2(16);
    const hash = SHA256(req.body.password + salt).toString(encBase64);
    const token = uid2(32);
    const newUser = new User({
      username: req.body.username,
      email: req.body.email,
      token: token,
      hash: hash,
      salt: salt,
    });

    await newUser.save();
    console.log("Utilisateur enregistré avec succès :", newUser);

    // Créer l'objet de réponse
    const responseObj = {
      _id: newUser._id,
      token: newUser.token,
      account: { username: newUser.username },
    };

    return res
      .status(201)
      .json({ message: "Nouveau compte créé", user: responseObj });
  } catch (error) {
    console.error("Erreur lors de la création du compte :", error);
    return res.status(500).json({ message: error.message });
  }
});

app.post("/login", async (req, res) => {
  try {
    console.log("Je suis dans la route /login", req.body);

    const userFound = await User.findOne({ username: req.body.username });

    if (!userFound) {
      console.log("Utilisateur non trouvé :", req.body.username);
      return res.status(400).json("Username ou mot de passe incorrect");
    }

    // Vérifier le mot de passe en comparant les hashes
    const newHash = SHA256(req.body.password + userFound.salt).toString(
      encBase64
    );
    if (newHash === userFound.hash) {
      console.log(
        "Authentification réussie pour l'utilisateur :",
        userFound.username
      );
      const responseObj = {
        _id: userFound._id,
        token: userFound.token,
        account: { username: userFound.username },
      };

      return res.status(200).json(responseObj);
    } else {
      console.log(
        "Mot de passe incorrect pour l'utilisateur :",
        userFound.username
      );
      return res.status(401).json("Email ou mot de passe incorrect");
    }
  } catch (error) {
    console.error("Erreur lors de l'authentification :", error);
    return res.status(500).json({ message: error.message });
  }
});

app.all("*", (req, res) => {
  console.log("Route non trouvée :", req.originalUrl);
  return res.status(404).json("404 NOT FOUND");
});
app.listen(3000, () => {
  console.log("Server started");
});
