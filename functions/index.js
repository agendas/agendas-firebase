const functions   = require('firebase-functions');
const firebase    = require("firebase-admin");
const fs          = require("fs");
const path        = require("path");
const url         = require("url");
const mustache    = require("mustache");
const crypto      = require("crypto");

const allowedScopes = {
  "email": "Know your email address",
  "username-read": "Know your username",
  "agenda-read": "View your agendas, tags, and tasks",
  "agenda-write": "Edit your agendas, tags, and tasks",
  "agenda-share": "Share your agendas with others"
};

const defaultTokenExpiration = 604800;

const serviceAccount = require("./service-account.json");

firebase.initializeApp({
  credential: firebase.credential.cert(serviceAccount),
  databaseURL: functions.config().firebase.databaseURL
});

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

    var expiration = Date.now() + (defaultTokenExpiration * 1000);
    return Promise.all([
      firebase.database().ref("/users/" + uid + "/apps/" + app + "/token").set({
        token: token,
        expiration: expiration
      }),
      Promise.resolve({
        access_token: token,
        token_type: "bearer",
        expires_in: defaultTokenExpiration
      }),
      firebase.database().ref("/users/" + uid + "/apps/" + app + "/scopes").set(scopesObject),
      firebase.database().ref("/tokens/" + token).set({
        token: token,
        expiration: expiration,
        app: app,
        user: uid
      })
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
              if (!data.exists()) {
                return generateToken(result.uid, req.body.client_id, scopes);
              } else if (new Date(data.val().expiration) <= new Date()) {
                return firebase.database().ref("/users/" + result.uid + "/apps/" + req.body.client_id + "/token").remove().then(function() {
                  return firebase.database().ref("/tokens/" + data.val().token).remove();
                }).then(function() {
                  return generateToken(result.uid, req.body.client_id, scopes);
                });
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

function verifyApiToken(token) {
  return firebase.database().ref("/tokens/" + token).once("value").then(function(data) {
    if (data.exists() && new Date(data.val().expiration) > new Date()) {
      var decodedToken = data.val();
      return Promise.all([
        firebase.database().ref("/apps/" + decodedToken.app).once("value"),
        firebase.database().ref("/users/" + decodedToken.user + "/apps/" + decodedToken.app).once("value"),
        Promise.resolve(decodedToken.user),
        Promise.resolve(decodedToken.expiration)
      ]);
    } else if (data.exists() && new Date(data.val().expiration) <= new Date()) {
      var decodedToken = data.val();
      firebase.database().ref("/tokens/" + token).remove();
      firebase.database().ref("/users/" + decodedToken.user + "/apps/" + decodedToken.app + "/token").remove();
      throw new Error("Token expired");
    } else {
      throw new Error("Invalid token");
    }
  }).then(function(results) {
    var app = results[0];
    if (app.exists()) {
      var userdata = results[1];
      if (userdata.exists()) {
        return {app: app.key, user: results[2], scopes: userdata.val().scopes, expiration: results[3]};
      } else {
        throw new Error("Invalid token");
      }
    } else {
      throw new Error("Invalid token");
    }
  });
};

function getApiCalls(app) {
  return firebase.database().ref("/apps/" + app + "/nextCycle").once("value").then(function(data) {
    if ((!data.exists()) || new Date(data.val()) < new Date()) {
      var nextCycle = new Date();
      nextCycle.setMonth(nextCycle.getMonth() + 1);
      nextCycle.setDate(0);
      nextCycle.setHours(0);
      nextCycle.setMinutes(0);
      nextCycle.setSeconds(0);
      nextCycle.setMilliseconds(0);
      return Promise.all([
        firebase.database().ref("/apps/" + app + "/maxCalls").once("value"),
        firebase.database().ref("/apps/" + app + "/apiCalls").set(0),
        data.ref.set(nextCycle.toJSON())
      ]).then(function(results) {
        return {calls: 0, max: results[0].val()};
      });
    } else {
      return Promise.all([
        firebase.database().ref("/apps/" + app + "/maxCalls").once("value"),
        firebase.database().ref("/apps/" + app + "/apiCalls").once("value")
      ]).then(function(results) {
        return {calls: results[1].val(), max: results[0].val()};
      });
    }
  });
};

function checkApiCalls(app, resolveArg) {
  return getApiCalls(app).then(function(result) {
    if (result.calls >= result.max) {
      throw new Error("Max API calls reached");
    } else {
      firebase.database().ref("/apps/" + app + "/apiCalls").set(result.calls + 1);
      return resolveArg;
    }
  });
};

function startApiCall(req, res) {
  res.set("Access-Control-Allow-Origin", "*");
  // res.set("Cache-Control", "no-cache, no-store, must-revalidate");

  if (req.query.pretty && req.query.pretty !== "0") {
    req.app.set("json spaces", "  ");
  } else {
    req.app.set("json spaces", null);
  }

  var token;
  if (req.get("Authorization")) {
    var parts = req.get("Authorization").split(" ");
    if (parts[0] === "Bearer") {
      token = parts[1];
    } else {
      res.sendStatus(400);
      return Promise.reject("Invalid token type");
    }
  } else if (req.query.token) {
    token = req.query.token;
  } else {
    res.sendStatus(400);
    return Promise.reject("Missing token");
  }

  return verifyApiToken(token).catch(function(e) {
    res.status(401);
    res.send(e.message);
    throw e;
  }).then(function(decodedToken) {
    return checkApiCalls(decodedToken.app, decodedToken).catch(function(e) {
      res.sendStatus(429);
      throw e;
    });
  });
};

function send405(res) {
  if (!res.get("Access-Control-Allow-Origin")) {
    res.set("Access-Control-Allow-Origin", "*");
  }

  res.sendStatus(405);
};

function handleOptionsRequest(req, res, methods) {
  res.set("Access-Control-Allow-Origin", "*");
  res.set("Access-Control-Allow-Methods", methods.join(", "));
  res.set("Access-Control-Allow-Headers", "Authorization, Content-Type");
  res.sendStatus(200);
}

exports.verify = functions.https.onRequest(function(req, res) {
  if (req.method === "GET") {
    startApiCall(req, res).then(function(token) {
      res.json({
        scopes: token.scopes,
        expires_in: Math.round((token.expiration - Date.now()) / 1000)
      });
    }).catch(function(e) {
      console.log(e);
      if (!res.headersSent) {
        res.sendStatus(500);
      }
    });
  } else if (req.method === "OPTIONS") {
    handleOptionsRequest(req, res, ["GET"]);
  } else {
    send405(res);
  }
});

exports.email = functions.https.onRequest(function(req, res) {
  if (req.method === "GET") {
    startApiCall(req, res).then(function(token) {
      if (!token.scopes.email) {
        res.sendStatus(403);
        throw null;
      }
      return firebase.auth().getUser(token.user);
    }).then(function(user) {
      res.status(200);
      res.json({email: user.email});
    }).catch(function(e) {
      if (e) {
        console.log(e);
      }
      if (!res.headersSent) {
        res.sendStatus(500);
      }
    });
  } else if (req.method === "OPTIONS") {
    handleOptionsRequest(req, res, ["GET"]);
  } else {
    send405(res);
  }
});

exports.username = functions.https.onRequest(function(req, res) {
  if (req.method === "GET") {
    startApiCall(req, res).then(function(token) {
      if (!token.scopes["username-read"]) {
        res.sendStatus(403);
        throw null;
      }
      return firebase.database().ref("/users/" + token.user + "/username").once("value");
    }).then(function(username) {
      res.status(200);
      res.json({username: username.val() || false});
    }).catch(function(e) {
      if (e) {
        console.log(e);
      }
      if (!res.headersSent) {
        res.sendStatus(500);
      }
    });
  } else if (req.method === "OPTIONS") {
    handleOptionsRequest(req, res, ["GET"]);
  } else {
    send405(res);
  }
});

exports.agendas = functions.https.onRequest(function(req, res) {
  if (req.method === "GET") {
    startApiCall(req, res).then(function(token) {
      if (token.scopes["agenda-read"]) {
        return firebase.database().ref("/users/" + token.user + "/agendas").once("value");
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(list) {
      if (list.exists()) {
        var user = list.ref.parent.key;
        return Promise.all(Object.keys(list.val()).map(function(agenda) {
          return firebase.database().ref("/permissions/" + agenda).child(user).once("value");
        })).then(function(permissions) {
          return Promise.all(permissions.filter(function(permission) {
            return permission.exists();
          }).map(function(permission) {
            return firebase.database().ref("/agendas/" + permission.ref.parent.key).once("value");
          }));
        }).then(function(agendas) {
          return agendas.map(function(data) {
            var agenda = data.val();
            agenda.id = data.key;
            return agenda;
          });
        });
      } else {
        return [];
      }
    }).then(function(agendas) {
      res.json(agendas);
    }).catch(function(e) {
      console.log(e);
      if (!res.headersSent) {
        res.sendStatus(500);
      }
    });
  } else if (req.method === "POST") {
    startApiCall(req, res).then(function(token) {
      if (!token.scopes["agenda-write"]) {
        res.sendStatus(403);
        throw null;
      }

      if (req.body.name && typeof req.body.name !== "string") {
        res.status(400);
        res.send("Invalid Name");
      }

      var ref = firebase.database().ref("/agendas/").push();
      return Promise.all([
        ref.key,
        token.user,
        ref.set({
          name: req.body.name || null
        }),
      ]);
    }).then(function(result) {
      var key = result[0];
      var user = result[1];
      var permissions = {};
      permissions[user] = "editor";
      return Promise.all([
        key,
        user,
        firebase.database().ref("/permissions/" + key).set(permissions)
      ]);
    }).then(function(result) {
      var key = result[0];
      return Promise.all([
        key,
        firebase.database().ref("/users/" + result[1] + "/agendas/" + key).set(true)
      ]);
    }).then(function(result) {
      res.status(201);
      res.json({ok: true, id: result[0]});
    }).catch(function(e) {
      if (!res.headersSent) { res.sendStatus(500); }
      if (e) { console.log(e); }
    });
  } else if (req.method === "OPTIONS") {
    handleOptionsRequest(req, res, ["GET", "POST"]);
  } else {
    send405(res);
  }
});

exports.agenda = functions.https.onRequest(function(req, res) {
  var agenda = path.basename(req.path);

  if (req.method === "GET") {
    startApiCall(req, res).then(function(token) {
      if (!token.scopes["agenda-read"]) {
        res.sendStatus(403);
        throw null;
      }

      if (agenda) {
        return firebase.database().ref("/permissions/" + agenda).child(token.user).once("value");
      } else {
        res.status(400);
        res.send("Missing Agenda");
        throw null;
      }
    }).then(function(data) {
      if (data.exists()) {
        return firebase.database().ref("/agendas/" + agenda).once("value");
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(data) {
      var agenda = data.val();
      agenda.id  = data.key;
      res.json(agenda);
    }).catch(function(e) {
      if (!res.headersSent) {
        res.sendStatus(500);
      }
      if (e) {
        console.log(e);
      }
    });
  } else if (req.method === "PUT") {
    startApiCall(req, res).then(function(token) {
      if (!token.scopes["agenda-write"]) {
        res.sendStatus(403);
        throw null;
      }

      if (req.body.name && typeof req.body.name !== "string") {
        res.status(400);
        res.send("Invalid Name");
      }

      return firebase.database().ref("/permissions/" + agenda).child(token.user).once("value");
    }).then(function(permission) {
      if (permission.val() === "editor") {
        return firebase.database().ref("/agendas/" + agenda).set({
          name: req.body.name || null
        });
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(result) {
      res.status(200);
      res.json({ok: true});
    }).catch(function(e) {
      if (!res.headersSent) { res.sendStatus(500); }
      if (e) { console.log(e); }
    });
  } else if (req.method === "PATCH") {
    startApiCall(req, res).then(function(token) {
      if (!token.scopes["agenda-write"]) {
        res.sendStatus(403);
        throw null;
      }

      if (req.body.name && typeof req.body.name !== "string") {
        res.status(400);
        res.send("Invalid Name");
      }

      return firebase.database().ref("/permissions/" + agenda).child(token.user).once("value");
    }).then(function(permission) {
      if (permission.val() === "editor") {
        var ref = firebase.database().ref("/agendas/" + agenda);

        return Promise.all(["name"].filter(function(key) {
          return req.body[key];
        }).map(function(key) {
          return ref.child(key).set(req.body[key]);
        }));
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(result) {
      res.status(200);
      res.json({ok: true});
    }).catch(function(e) {
      if (!res.headersSent) { res.sendStatus(500); }
      if (e) { console.log(e); }
    });
  } else if (req.method === "DELETE") {
    startApiCall(req, res).then(function(token) {
      if (!token.scopes["agenda-write"]) {
        res.sendStatus(403);
        throw null;
      }

      return Promise.all([
        token.user,
        firebase.database().ref("/permissions/" + agenda).once("value")
      ]);
    }).then(function(result) {
      var user = result[0];
      var permissions = result[1];

      if (permissions.child(user).val() === "editor") {
        var promises = [];
        permissions.forEach(function(permission) {
          promises.push(firebase.database().ref("/users/" + permission.key + "/agendas/" + agenda).remove());
        });

        return Promise.all([
          firebase.database().ref("/agendas/" + agenda).remove(),
          firebase.database().ref("/permissions/" + agenda).remove(),
          firebase.database().ref("/categories/" + agenda).remove(),
          firebase.database().ref("/tasks/" + agenda).remove(),
          Promise.all(promises)
        ]);
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function() {
      res.status(200);
      res.json({ok: true});
    }).catch(function(e) {
      if (!res.headersSent) { res.sendStatus(500); }
      if (e) { console.log(e); }
    });
  } else if (req.method === "OPTIONS") {
    handleOptionsRequest(req, res, ["GET", "PUT", "PATCH", "DELETE"]);
  } else {
    send405(res);
  }
});

exports.tags = functions.https.onRequest(function(req, res) {
  var agenda = path.basename(req.path);

  if (req.method === "GET") {
    startApiCall(req, res).then(function(token) {
      if (!token.scopes["agenda-read"]) {
        res.sendStatus(403);
        throw null;
      }

      if (agenda) {
        return firebase.database().ref("/permissions/" + agenda).child(token.user).once("value");
      } else {
        res.status(400);
        res.send("Missing Agenda");
        throw null;
      }
    }).then(function(permission) {
      if (permission.exists()) {
        return firebase.database().ref("/categories/" + agenda).once("value");
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(data) {
      if (data.exists()) {
        var categories = [];
        data.forEach(function(child) {
          var category = child.val();
          category.id  = child.key;
          categories.push(category);
        });
        return categories;
      } else {
        return [];
      }
    }).then(function(categories) {
      res.json(categories);
    }).catch(function(e) {
      if (!res.headersSent) {
        res.sendStatus(500);
      }

      if (e) {
        console.log(e);
      }
    });
  } else if (req.method === "POST") {
    startApiCall(req, res).then(function(token) {
      if (!token.scopes["agenda-write"]) {
        res.sendStatus(403);
        throw null;
      }

      if ((req.body.name && typeof req.body.name !== "string") || (req.body.color && typeof req.body.color !== "string") || !(req.body.name || req.body.color)) {
        res.sendStatus(400);
        throw null;
      }

      return firebase.database().ref("/permissions/" + agenda).child(token.user).once("value");
    }).then(function(permission) {
      if (permission.val() === "editor") {
        var tagRef = firebase.database().ref("/categories/" + agenda).push();
        return Promise.all([
          Promise.resolve(tagRef.key),
          tagRef.set({
            name: req.body.name || null,
            color: req.body.color || null
          })
        ]);
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(result) {
      var key = result[0];
      res.status(201);
      res.json({ok: true, id: key});
    }).catch(function(e) {
      if (!res.headersSent) {
        res.sendStatus(500);
      }

      if (e) {
        console.log(e);
      }
    });
  } else if (req.method === "OPTIONS") {
    handleOptionsRequest(req, res, ["GET", "POST"]);
  } else {
    send405(res);
  }
});

exports.tag = functions.https.onRequest(function(req, res) {
  var agenda = path.basename(path.dirname(req.path));
  var tag    = path.basename(req.path);

  if (req.method === "GET") {
    startApiCall(req, res).then(function(token) {
      if (!token.scopes["agenda-read"]) {
        res.sendStatus(403);
        throw null;
      }

      if (agenda && tag) {
        return firebase.database().ref("/permissions/" + agenda).child(token.user).once("value");
      } else if (agenda) {
        res.status(400);
        res.send("Missing Tag");
        throw null;
      } else {
        res.status(400);
        res.send("Missing Agenda");
        throw null;
      }
    }).then(function(permission) {
      if (permission.exists()) {
        return firebase.database().ref("/categories/" + agenda).child(tag).once("value");
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(data) {
      if (data.exists()) {
        var tagData = data.val();
        tagData.id = data.key;
        return Promise.all([
          Promise.resolve(tagData),
          firebase.database().ref("/tasks/" + agenda).orderByChild("tags/" + tagData.id).equalTo(true).once("value")
        ]);
      } else {
        res.sendStatus(404);
        throw null;
      }
    }).then(function(results) {
      var tagData = results[0];
      tagData.tasks = [];
      results[1].forEach(function(data) {
        var task = data.val();
        task.id  = data.key;
        tagData.tasks.push(task);
      });
      res.json(tagData);
    }).catch(function(e) {
      if (!res.headersSent) { res.sendStatus(500) }
      if (e) { console.log(e) }
    });
  } else if (req.method === "PUT") {
    startApiCall(req, res).then(function(token) {
      if (!token.scopes["agenda-write"]) {
        res.sendStatus(403);
        throw null;
      }

      if ((req.body.name && typeof req.body.name !== "string") || (req.body.color && typeof req.body.color !== "string") || !(req.body.name || req.body.color)) {
        res.sendStatus(400);
        throw null;
      }

      return firebase.database().ref("/permissions/" + agenda).child(token.user).once("value");
    }).then(function(permission) {
      if (permission.val() === "editor") {
        return firebase.database().ref("/categories/" + agenda).child(tag).once("value");
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(tag) {
      if (tag.exists()) {
        return tag.ref.set({
          name: req.body.name || null,
          color: req.body.color || null
        });
      } else {
        res.sendStatus(404);
        throw null;
      }
    }).then(function() {
      res.status(200);
      res.json({ok: true});
    }).catch(function(e) {
      if (!res.headersSent) { res.sendStatus(500); }
      if (e) { console.log(e); }
    });
  } else if (req.method === "PATCH") {
    startApiCall(req, res).then(function(token) {
      if (!token.scopes["agenda-write"]) {
        res.sendStatus(403);
        throw null;
      }

      if ((req.body.name && typeof req.body.name !== "string") || (req.body.color && typeof req.body.color !== "string")) {
        res.sendStatus(400);
        throw null;
      }

      return firebase.database().ref("/permissions/" + agenda).child(token.user).once("value");
    }).then(function(permission) {
      if (permission.val() === "editor") {
        return firebase.database().ref("/categories/" + agenda).child(tag).once("value");
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(tag) {
      if (tag.exists()) {
        return Promise.all(["name", "color"].filter(function(key) {
          return req.body[key];
        }).map(function(key) {
          return tag.ref.child(key).set(req.body[key]);
        }));
      } else {
        res.sendStatus(404);
        throw null;
      }
    }).then(function() {
      res.status(200);
      res.json({ok: true});
    }).catch(function(e) {
      if (!res.headersSent) { res.sendStatus(500); }
      if (e) { console.log(e); }
    });
  } else if (req.method === "DELETE") {
    startApiCall(req, res).then(function(token) {
      if (!token.scopes["agenda-write"]) {
        res.sendStatus(403);
        throw null;
      }

      return firebase.database().ref("/permissions/" + agenda).child(token.user).once("value");
    }).then(function(permission) {
      if (permission.val() === "editor") {
        return firebase.database().ref("/categories/" + agenda).child(tag).remove();
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function() {
      res.status(200);
      res.json({ok: true});
    }).catch(function(e) {
      if (!res.headersSent) { res.sendStatus(500); }
      if (e) { console.log(e); }
    });
  } else if (req.method === "OPTIONS") {
    handleOptionsRequest(req, res, ["GET", "PUT", "PATCH", "DELETE"]);
  } else {
    send405(res);
  }
});

exports.tasks = functions.https.onRequest(function(req, res) {
  var agenda = path.basename(req.path);

  if (req.method === "GET") {
    startApiCall(req, res).then(function(token) {
      if (!token.scopes["agenda-read"]) {
        res.sendStatus(403);
        throw null;
      }

      if (agenda) {
        return firebase.database().ref("/permissions/" + agenda).child(token.user).once("value");
      } else {
        res.status(400);
        res.send("Missing Agenda");
        throw null;
      }
    }).then(function(permission) {
      if (permission.exists()) {
        return firebase.database().ref("/tasks/" + agenda).once("value");
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(data) {
      if (data.exists()) {
        var tasks = [];
        data.forEach(function(child) {
          var task = child.val();
          task.id  = child.key;
          if (task.category) {
            if (!task.tags) {
              task.tags = {};
              task.tags[task.category] = true;
            }
            delete task.category;
          }
          if (task.deadlineTime && !task.deadline) {
            delete task.deadlineTime;
          }
          if (task.repeat === "") {
            delete task.repeat;
          }
          if (task.repeatEnds === "") {
            delete task.repeatEnds;
          }
          if (task.priority === 0) {
            delete task.priority;
          }
          tasks.push(task);
        });
        return tasks;
      } else {
        return [];
      }
    }).then(function(tasks) {
      res.json(tasks);
    }).catch(function(e) {
      if (!res.headersSent) {
        res.sendStatus(500);
      }

      if (e) {
        console.log(e);
      }
    })
  } else if (req.method === "POST") {
    startApiCall(req, res).then(function(token) {
      if (!token.scopes["agenda-write"]) {
        res.sendStatus(403);
        throw null;
      }

      if (
        (req.body.name && typeof req.body.name !== "string") ||
        (req.body.repeat && typeof req.body.repeat !== "string") ||
        (req.body.deadline && isNaN(new Date(req.body.deadline).getTime())) ||
        (req.body.deadlineTime && typeof req.body.deadlineTime !== "boolean") ||
        (req.body.deadlineTime && !req.body.deadline) ||
        (req.body.repeat && !req.body.deadline) ||
        (req.body.repeatEnds && !req.body.repeat) ||
        (req.body.repeatEnds && isNaN(new Date(req.body.repeatEnds).getTime())) ||
        (req.body.tags && (typeof req.body.tags === "string" || req.body.tags.length === undefined)) ||
        ((req.body.priority !== undefined || req.body.priority !== null) && typeof req.body.priority !== "number") ||
        (req.body.notes && typeof req.body.notes !== "string") ||
        !(req.body.name || req.body.deadline || req.body.deadlineTime || req.body.repeat || req.body.repeatEnds || req.body.tags || req.body.priority || req.body.notes)
      ) {
        res.sendStatus(400);
        throw null;
      }

      return firebase.database().ref("/permissions/" + agenda).child(token.user).once("value");
    }).then(function(permission) {
      if (permission.val() === "editor") {
        var taskRef = firebase.database().ref("/tasks/" + agenda).push();
        if (req.body.tags) {
          var tags = {};
          req.body.tags.forEach(function(tag) {
            tags[tag] = true;
          });
          return {ref: taskRef, tags: tags};
        } else {
          return {ref: taskRef};
        }
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(result) {
      var taskRef = result.ref;
      var tags    = result.tags;

      return Promise.all([
        Promise.resolve(taskRef.key),
        taskRef.set({
          name: req.body.name || null,
          deadline: req.body.deadline || null,
          deadlineTime: req.body.deadlineTime || null,
          repeat: req.body.repeat || null,
          repeatEnds: req.body.repeatEnds || null,
          tags: tags,
          priority: req.body.priority || null,
          notes: req.body.notes || null
        })
      ]);
    }).then(function(result) {
      var key = result[0];
      res.status(201);
      res.json({ok: true, id: key});
    }).catch(function(e) {
      if (!res.headersSent) {
        res.sendStatus(500);
      }

      if (e) {
        console.log(e);
      }
    });
  } else if (req.method === "OPTIONS") {
    handleOptionsRequest(req, res, ["GET", "POST"]);
  } else {
    send405(res);
  }
});

exports.task = functions.https.onRequest(function(req, res) {
  var agenda = path.basename(path.dirname(req.path));
  var task   = path.basename(req.path);

  if (req.method === "GET") {
    startApiCall(req, res).then(function(token) {
      if (!token.scopes["agenda-read"]) {
        res.sendStatus(403);
        throw null;
      }

      if (agenda && task) {
        return firebase.database().ref("/permissions/" + agenda).child(token.user).once("value");
      } else if (agenda) {
        res.status(400);
        res.send("Missing Task");
        throw null;
      } else {
        res.status(400);
        res.send("Missing Agenda");
        throw null;
      }
    }).then(function(permission) {
      if (permission.exists()) {
        return firebase.database().ref("/tasks/" + agenda).child(task).once("value");
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(data) {
      if (data.exists()) {
        var taskData = data.val();
        taskData.id = data.key;

        if (taskData.category) {
          if (!taskData.tags) {
            taskData.tags = {};
            taskData.tags[task.category] = true;
          }
          delete taskData.category;
        }
        if (taskData.deadlineTime && !taskData.deadline) {
          delete taskData.deadlineTime;
        }
        if (taskData.repeat === "") {
          delete taskData.repeat;
        }
        if (taskData.repeatEnds === "") {
          delete taskData.repeatEnds;
        }
        if (!taskData.priority) {
          delete taskData.priority;
        }

        if (taskData.tags) {
          return Promise.all(Object.keys(taskData.tags).map(function(tag) {
            return firebase.database().ref("/categories/" + agenda).child(tag).once("value");
          })).then(function(tags) {
            taskData.tags = tags.map(function(data) {
              var tag = data.val();
              if (tag) {
                tag.id = data.key;
              }
              return tag;
            }).filter(function(tag) {
              return !!tag;
            });

            return taskData;
          });
        } else {
          return taskData;
        }
      } else {
        res.sendStatus(404);
        throw null;
      }
    }).then(function(task) {
      res.json(task);
    }).catch(function(e) {
      if (!res.headersSent) { res.sendStatus(500) }
      if (e) { console.log(e) }
    });
  } else if (req.method === "PUT") {
    startApiCall(req, res).then(function(token) {
      if (!token.scopes["agenda-write"]) {
        res.sendStatus(403);
        throw null;
      }

      if (
        (req.body.name && typeof req.body.name !== "string") ||
        (req.body.repeat && typeof req.body.repeat !== "string") ||
        (req.body.deadline && isNaN(new Date(req.body.deadline).getTime())) ||
        (req.body.deadlineTime && typeof req.body.deadlineTime !== "boolean") ||
        (req.body.deadlineTime && !req.body.deadline) ||
        (req.body.repeat && !req.body.deadline) ||
        (req.body.repeatEnds && !req.body.repeat) ||
        (req.body.repeatEnds && isNaN(new Date(req.body.repeatEnds).getTime())) ||
        (req.body.tags && (typeof req.body.tags === "string" || req.body.tags.length === undefined)) ||
        ((req.body.priority !== undefined || req.body.priority !== null) && typeof req.body.priority !== "number") ||
        (req.body.notes && typeof req.body.notes !== "string") ||
        !(req.body.name || req.body.deadline || req.body.deadlineTime || req.body.repeat || req.body.repeatEnds || req.body.tags || req.body.priority || req.body.notes)
      ) {
        res.sendStatus(400);
        throw null;
      }

      return firebase.database().ref("/permissions/" + agenda).child(token.user).once("value");
    }).then(function(permission) {
      if (permission.val() === "editor") {
        return firebase.database().ref("/tasks/" + agenda).child(task).once("value");
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(task) {
      if (task.exists()) {
        /* return Promise.all(["name", "deadline", "deadlineTime", "repeat", "repeatEnds", "tags", "notes"].filter(function(key) {
          return req.body[key] !== undefined;
        }).map(function(key) {
          if (key === "tags") {
            var tags = {};
            req.body.tags.forEach(function(tag) {
              tags[tag] = true;
            });
            return task.ref.child("tags").set(tags);
          } else {
            return task.ref.child(key).set(req.body[key]);
          }
        })); */

        var tags = null;
        if (req.body.tags) {
          tags = {};
          req.body.tags.forEach(function(tag) {
            tags[tag] = true;
          });
        }

        return task.ref.set({
          name: req.body.name || null,
          deadline: req.body.deadline || null,
          deadlineTime: req.body.deadlineTime || null,
          repeat: req.body.repeat || null,
          repeatEnds: req.body.repeatEnds || null,
          tags: tags,
          priority: req.body.priority || null,
          notes: req.body.notes || null
        })
      } else {
        res.sendStatus(404);
        throw null;
      }
    }).then(function() {
      res.status(200);
      res.json({ok: true});
    }).catch(function(e) {
      if (!res.headersSent) { res.sendStatus(500); }
      if (e) { console.log(e); }
    });
  } else if (req.method === "PATCH") {
    startApiCall(req, res).then(function(token) {
      if (!token.scopes["agenda-write"]) {
        res.sendStatus(403);
        throw null;
      }

      if (
        (req.body.name && typeof req.body.name !== "string") ||
        (req.body.repeat && typeof req.body.repeat !== "string") ||
        (req.body.deadline && isNaN(new Date(req.body.deadline).getTime())) ||
        (req.body.deadlineTime && typeof req.body.deadlineTime !== "boolean") ||
        (req.body.repeatEnds && isNaN(new Date(req.body.repeatEnds).getTime())) ||
        (req.body.tags && (typeof req.body.tags === "string" || req.body.tags.length === undefined)) ||
        ((req.body.priority !== undefined || req.body.priority !== null) && typeof req.body.priority !== "number") ||
        (req.body.notes && typeof req.body.notes !== "string")
      ) {
        res.sendStatus(400);
        throw null;
      }

      return firebase.database().ref("/permissions/" + agenda).child(token.user).once("value");
    }).then(function(permission) {
      if (permission.val() === "editor") {
        return firebase.database().ref("/tasks/" + agenda).child(task).once("value");
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(task) {
      if (task.exists()) {
        return Promise.all(["name", "deadline", "deadlineTime", "repeat", "repeatEnds", "tags", "priority", "notes"].filter(function(key) {
          return req.body[key] !== undefined;
        }).map(function(key) {
          if (key === "tags") {
            var tags = {};
            req.body.tags.forEach(function(tag) {
              tags[tag] = true;
            });
            return task.ref.child("tags").set(tags);
          } else {
            return task.ref.child(key).set(req.body[key]);
          }
        }));
      } else {
        res.sendStatus(404);
        throw null;
      }
    }).then(function() {
      res.status(200);
      res.json({ok: true});
    }).catch(function(e) {
      if (!res.headersSent) { res.sendStatus(500); }
      if (e) { console.log(e); }
    });
  } else if (req.method === "DELETE") {
    startApiCall(req, res).then(function(token) {
      if (!token.scopes["agenda-write"]) {
        res.sendStatus(403);
        throw null;
      }

      return firebase.database().ref("/permissions/" + agenda).child(token.user).once("value");
    }).then(function(permission) {
      if (permission.val() === "editor") {
        return firebase.database().ref("/tasks/" + agenda).child(task).remove();
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function() {
      res.status(200);
      res.json({ok: true});
    }).catch(function(e) {
      if (!res.headersSent) { res.sendStatus(500); }
      if (e) { console.log(e); }
    });
  } else if (req.method === "OPTIONS") {
    handleOptionsRequest(req, res, ["GET", "PUT", "PATCH", "DELETE"]);
  } else {
    send405(res);
  }
});

exports.revoke = functions.https.onRequest(function(req, res) {
  var app = path.basename(req.path);
  if (req.method === "POST") {
    res.set("Access-Control-Allow-Origin", "*");
    if (req.get("Authorization") && app) {
      firebase.auth().verifyIdToken(req.get("Authorization")).catch(function(e) {
        res.sendStatus(400);
        console.log(e);
        throw null;
      }).then(function(token) {
        return firebase.database().ref("/users/" + token.uid + "/apps/" + app + "/token/token").once("value");
      }).then(function(token) {
        if (token.exists()) {
          return Promise.all([
            token.ref.parent.parent.remove(),
            firebase.database().ref("/tokens/" + token.val()).remove()
          ]);
        } else {
          res.sendStatus(404);
          throw null;
        }
      }).then(function() {
        res.status(200);
        res.json({ok: true});
      }).catch(function(e) {
        if (!res.headersSent) { res.sendStatus(500); }
        if (e) { console.log(e); }
      });
    } else {
      res.sendStatus(400);
    }
  } else if (req.method === "OPTIONS") {
    handleOptionsRequest(req, res, ["POST"]);
  } else {
    send405(res);
  }
});
