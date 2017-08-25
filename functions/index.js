const functions   = require('firebase-functions');
const firebase    = require("firebase-admin");
const fs          = require("fs");
const path        = require("path");
const url         = require("url");
const mustache    = require("mustache");
const crypto      = require("crypto");

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
          responseType: req.query.response_type,
          scopes: JSON.stringify(result.scopes),
          scopeText: result.scopes.map(function(scope) {
            return {text: allowedScopes[scope]};
          }),
          redirectURL: result.app.oauth.redirectURL,
          redirectURLJSON: JSON.stringify(result.app.oauth.redirectURL),
          state: result.state,
          clientId: result.id
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

function generateToken(uid, app, scopes) {
  return new Promise(function(resolve, reject) {
    crypto.randomBytes(16, function(err, buf) {
      err ? reject(err) : resolve(buf.toString("base64").replace("/", "-"));
    });
  }).then(function(token) {
    var scopesObject = {};
    scopes.forEach(function(scope) {
      scopesObject[scope] = true;
    });
    return Promise.all([
      firebase.database().ref("/users/" + uid + "/apps/" + app + "/token").set({
        token: token,
        expiration: Date.now() + 3600 * 1000
      }),
      Promise.resolve({
        access_token: token,
        token_type: "bearer",
        expires_in: 3600
      }),
      firebase.database().ref("/users/" + uid + "/apps/" + app + "/scopes").set(scopesObject)
    ]);
  }).then(function(results) {
    return results[1];
  });
};

exports.allowapp = functions.https.onRequest(function(req, res) {
  if (req.method === "POST") {
    if (req.body && req.body.redirect_url && req.body.firebase_token && req.body.response_type && req.body.scopes && req.body.client_id) {
      var scopes;
      try {
        scopes = JSON.parse(req.body.scopes);
      } catch(e) {
        res.sendStatus(400);
      }

      for (var scope of scopes) {
        if (!allowedScopes[scope]) {
          scopes = null;
          res.sendStatus(400);
          break;
        }
      }

      if (scopes) {
        firebase.auth().verifyIdToken(req.body.firebase_token).catch(function(e) {
          res.sendStatus(403);
        }).then(function(decodedToken) {
          return Promise.all([
            firebase.database().ref("/apps/" + req.body.client_id).once("value"),
            Promise.resolve(decodedToken.uid)
          ]);
        }).then(function(results) {
          var data = results[0];
          var uid  = results[1];

          if (data.exists()) {
            if (data.val().oauth.redirectURL === req.body.redirect_url) {
              return Promise.all([
                firebase.database().ref("/users/" + uid + "/apps/" + data.key).once("value"),
                Promise.resolve(uid)
              ]);
            }
          } else {
            res.sendStatus(404);
            throw null;
          }
        }).then(function(results) {
          if (results[0].exists() && results[0].child("scopes").exists()) {
            var grantedScopes = results[0].val().scopes;
            var extraScopes   = false;
            for (var scope of scopes) {
              if (!grantedScopes[scope]) {
                extraScopes = true;
                break;
              }
            }
            return {generateToken: extraScopes, uid: results[1]};
          } else {
            return {generateToken: true, uid: results[1]};
          }
        }).then(function(result) {
          if (result.generateToken) {
            return generateToken(result.uid, req.body.client_id, scopes);
          } else {
            return firebase.database().ref("/users/" + result.uid + "/apps/" + req.body.client_id + "/token").once("value").then(function(data) {
              if ((!data.exists()) || new Date(data.val().expiration) <= new Date()) {
                return generateToken(result.uid, req.body.client_id, scopes);
              } else {
                return {
                  access_token: data.val().token,
                  token_type: "bearer",
                  expires_in: Math.round((new Date(data.val().expiration).getTime() - Date.now()) / 1000)
                };
              }
            });
          }
        }).then(function(query) {
          var redirect = url.parse(req.body.redirect_url);
          redirect.query = query;
          if (req.body.state) {
            redirect.query.state = req.body.state;
          }
          res.redirect(303, url.format(redirect));
        }).catch(function(e) {
          if (!res.headersSent) {
            res.sendStatus(500);
          }

          if (e) {
            console.log(e);
          }
        });
      }
    } else {
      res.sendStatus(400);
    }
  } else {
    res.sendStatus(405);
  }
});
