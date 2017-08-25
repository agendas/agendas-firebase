const functions   = require('firebase-functions');
const firebase    = require("firebase-admin");
const fs          = require("fs");
const path        = require("path");
const url         = require("url");
const mustache    = require("mustache");

const allowedScopes = {
  "agenda-read": "View your agendas, tags, and tasks",
  "agenda-write": "Edit your agendas, tags, and tasks",
  "agenda-share": "Share your agendas with others"
};

firebase.initializeApp(functions.config().firebase);

exports.ping = functions.https.onRequest(function(req, res) {
  res.status(200).send("Pong");
});

exports.authorize = functions.https.onRequest(function(req, res) {
  if (req.method === "GET") {
    if (req.query.response_type === "token") {
      firebase.database().ref("/apps/" + req.query.client_id).once("value").then(function(data) {
        if (data.exists()) {
          return {app: data.val(), id: data.key};
        } else {
          res.sendStatus(404);
          throw null;
        }
      }).then(function(data) {
        var app = data.app;
        var client_id = data.id;
        if (app.oauth.redirectURL !== req.query.redirect_url) {
          res.status(400);
          res.send("Bad Redirect URL");
          throw null;
        } else {
          if (req.query.scopes) {
            var scopes = req.query.scopes.split(",");

            var invalidScopes = false;
            for (var scope of scopes) {
              if (!allowedScopes[scope]) {
                invalidScopes = true;
                break;
              }
            }

            if (invalidScopes) {
              res.status(400);
              res.send("Invalid Scopes");
              throw null;
            } else {
              return new Promise(function(resolve, reject) {
                fs.readFile(path.join(__dirname, "authorize.html"), "utf8", function(err, data) {
                  err ? reject(err) : resolve({data: data, app: app, scopes: scopes, state: req.query.state, id: client_id});
                });
              });
            }
          } else {
            res.status(400);
            res.send("Invalid Scopes");
            throw null;
          }
        }
      }).then(function(result) {
        var html = mustache.render(result.data, {
          name: result.app.name,
          scopes: JSON.stringify(result.scopes),
          scopeText: result.scopes.map(function(scope) {
            return {text: allowedScopes[scope]};
          }),
          redirectURL: JSON.stringify(result.app.oauth.redirectURL),
          state: JSON.stringify(result.state),
          clientId: JSON.stringify(result.id)
        });
        res.status(200);
        res.type("html");
        res.send(html);
      }).catch(function(e) {
        if (!res.headersSent) {
          res.sendStatus(500);
        }
        if (e) {
          console.log(e);
        }
      });
    } else {
      res.sendStatus(501);
    }
  } else {
    res.sendStatus(405);
  }
});
