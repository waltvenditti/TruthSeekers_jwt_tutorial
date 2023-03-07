const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");
const fs = require("fs");
const fakeLocal = require("./fakeLocal.json");

app.get("/", (req, res) => {
  res.send("Homepage");
});

app.get("/createtoken", async (req, res) => {
  let user = {
    name: "joey",
    favColor: "blue",
    id: "123",
  };
  const token = jwt.sign({user: user}, "TOP_SECRET_KEY");
  console.log(token);
  await fs.writeFile(
    "fakeLocal.json",
    JSON.stringify({Authorizaton:`Bearer ${token}`}), (err) => {
      if (err) throw err;
      console.log("Updated the fake localstorage in the afke browser")
    }
  )
  res.send("You just make a token and stored it in the json file. Now visit /profile and /wrongsecret");
});

app.get("/profile", async (req, res) => {
  console.log("Authorization token: ", fakeLocal.Authorization);
  const result = await jwt.verify(
    fakeLocal.Authorization.substring(7),
    "TOP_SECRET_KEY"
  );
  result.message = "We were able to decrypt the token because we have a valid secret in the app, and the token. The users data is inside the token."
  console.log("result: ", result);
  res.json(result);
});

app.get("/wrongsecret", async (req, res, next) => {
  try {
    await jwt.verify(fakeLocal.Authorization.substring(7), "INCORRECT_SECRET");
    res.send("/profile");
  } catch (err) {
    console.log("err: ", err);
    return res.status(400).send("Your token is invalid.");
  }

  res.send("wrongsecret under construction");
});

app.listen(3000, () => {
  console.log("Listening on port 3000...")
});