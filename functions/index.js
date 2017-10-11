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

exports.authorize = functions.https.onRequest(function(req, res) {
  if (req.method === "GET") {
    if (req.query.response_type === "token" || req.query.response_type === "code") {
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
        if (req.query.response_type === "token" && app.oauth.redirectURL !== req.query.redirect_url) {
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
          redirectURL: req.query.redirect_url,
          redirectURLJSON: JSON.stringify(req.query.redirect_url),
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
            if (req.body.response_type !== "token" || data.val().oauth.redirectURL === req.body.redirect_url) {
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
          if (req.body.response_type === "token") {
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
          } else {
            return Promise.all([
              new Promise(function(resolve, reject) {
                if (result.generateToken) {
                  var scopesObject = {};
                  scopes.forEach(function(scope) {
                    scopesObject[scope] = true;
                  });
                  firebase.database().ref("/users/" + result.uid + "/apps/" + req.body.client_id + "/scopes").set(scopesObject).then(resolve).catch(reject);
                } else {
                  resolve();
                }
              }),
              Promise.all([
                new Promise(function(resolve, reject) {
                  crypto.randomBytes(18, function(err, buf) {
                    err ? reject(err) : resolve(buf.toString("base64").replace("/", "-"));
                  });
                }),
                firebase.database().ref("/users/" + result.uid + "/apps/" + req.body.client_id + "/code").once("value").then(function(data) {
                  if (data.exists()) {
                    return firebase.database().ref("/codes/" + data.val()).remove()
                  }
                })
              ]).then(function(results) {
                var code = results[0];
                var expiration = new Date(Date.now() + 60 * 1000);
                return Promise.all([
                  Promise.resolve({code: code}),
                  firebase.database().ref("/users/" + result.uid + "/apps/" + req.body.client_id + "/code").set(code),
                  firebase.database().ref("/codes/" + code).set({
                    expiration: expiration.toJSON(),
                    app: req.body.client_id,
                    user: result.uid,
                    redirect: req.body.redirect_url
                  })
                ]);
              })
            ]).then(function(result) {
              var query = result[1][0];
              if (req.body.state) {
                query.state = req.body.state;
              }
              return query;
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

exports.token = functions.https.onRequest(function(req, res) {
  if (req.method === "POST") {
    if (!((req.body.grant_type === "authorization_code" && req.body.code) || (req.body.grant_type === "refresh_token" && req.body.refresh_token)) || !req.body.client_secret) {
      res.status(400);
      res.json({ok: false, error: "invalid_request"});
      return;
    }

    var validatePromise = req.body.grant_type === "authorization_code" ? firebase.database().ref("/codes/" + req.body.code).once("value").then(function(data) {
      data.ref.remove();
      if (data.exists()) {
        firebase.database().ref("/users/" + data.val().user + "/apps/" + data.val().app + "/code").remove();
      }
      if (
        data.exists() &&
        ((req.body.redirect_url || req.body.redirect_uri) === data.val().redirect || !(req.body.redirect_url || req.body.redirect_uri)) &&
        new Date() <= new Date(data.val().expiration)
      ) {
        return {app: data.val().app, user: data.val().user};
      } else {
        res.status(400);
        res.json({ok: false, error: "invalid_grant"});
        throw null;
      }
    }) : firebase.database().ref("/refresh/" + req.body.refresh_token).once("value").then(function(data) {
      if (data.exists()) {
        return {app: data.val().app, user: data.val().user};
      } else {
        res.status(400);
        res.json({ok: false, error: "invalid_grant"});
        throw null;
      }
    });

    validatePromise.then(function(grant) {
      if (req.body.client_id === grant.app) {
        return Promise.all([firebase.database().ref("/apps/" + grant.app + "/oauth/secret").once("value"), grant]);
      } else {
        res.status(400);
        res.json({ok: false, error: "invalid_client"});
        throw null;
      }
    }).then(function(results) {
      var secret = results[0];
      var grant  = results[1];
      if (secret.val() === req.body.client_secret) {
        return Promise.all([
          firebase.database().ref("/users/" + grant.user + "/apps/" + grant.app + "/token").once("value").then(function(token) {
            token.ref.remove();

            if (token.child("token").exists()) {
              firebase.database().ref("/tokens/" + token.val().token).remove()
            }

            return Promise.all([new Promise(function(resolve, reject) {
              crypto.randomBytes(16, function(err, buf) {
                err ? reject(err) : resolve(buf.toString("base64").replace("/", "-"));
              });
            }), token.ref]);
          }).then(function(results) {
            var token      = results[0];
            var ref        = results[1];
            var expiration = new Date(Date.now() + 3600 * 1000);
            return Promise.all([
              token,
              ref.set({
                token: token,
                expiration: expiration.toJSON()
              }),
              firebase.database().ref("/tokens/" + token).set({
                expiration: expiration.toJSON(),
                app: grant.app,
                user: grant.user
              })
            ]);
          }),
          firebase.database().ref("/users/" + grant.user + "/apps/" + grant.app + "/refresh").once("value").then(function(refresh) {
            refresh.ref.remove();

            if (refresh.exists()) {
              firebase.database().ref("/refresh/" + refresh.val()).remove();
            }

            return Promise.all([new Promise(function(resolve, reject) {
              crypto.randomBytes(16, function(err, buf) {
                err ? reject(err) : resolve(buf.toString("base64").replace("/", "-"));
              });
            }), refresh.ref]);
          }).then(function(results) {
            var refresh    = results[0];
            var ref        = results[1];
            return Promise.all([
              refresh,
              ref.set(refresh),
              firebase.database().ref("/refresh/" + refresh).set({
                app: grant.app,
                user: grant.user
              })
            ]);
          })
        ]);
      } else {
        res.status(400);
        res.json({ok: false, error: "invalid_client"});
        throw null;
      }
    }).then(function(tokens) {
      res.status(200);
      res.json({access_token: tokens[0][0], refresh_token: tokens[1][0], token_type: "bearer", expires_in: 3600});
    }).catch(function(e) {
      if (!res.headersSent) {
        res.status(500);
        res.json({ok: false, error: "server_error"});
      }

      if (e) {
        console.log(e);
      }
    })
  } else {
    res.sendStatus(405);
  }
});

exports.newapp = functions.https.onRequest(function(req, res) {
  if (req.method === "POST") {
    res.set("Access-Control-Allow-Origin", "*");

    var auth = req.get("Authorization") && req.get("Authorization").split(" ");
    if ((!auth) || auth[0] !== "Firebase" || !auth[1]) {
      res.status(401);
      res.json({ok: false, error: "invalid_auth"});
      return;
    }

    firebase.auth().verifyIdToken(auth[1]).catch(function(e) {
      res.status(401);
      res.json({ok: false, error: "invalid_auth"});
      throw e;
    }).then(function(decodedToken) {
      return firebase.database().ref("/users/" + decodedToken.uid + "/maxApps").once("value");
    }).then(function(maxApps) {
      if (typeof maxApps.val() !== "number" || maxApps.val() === 0) {
        res.status(403);
        res.json({ok: false, error: "app_limit_reached"});
        throw null;
      } else if (maxApps.val() > 0) {
        return firebase.database().ref("/users/" + maxApps.ref.parent.key + "/createdApps").once("value").then(function(apps) {
          if (apps.exists() && apps.numChildren() >= maxApps.val()) {
            res.status(403);
            res.json({ok: false, error: "app_limit_reached"});
            throw null;
          } else {
            return maxApps.ref.parent.key;
          }
        });
      } else {
        return maxApps.ref.parent.key;
      }
    }).then(function(uid) {
      var appKey = firebase.database().ref("/apps/").push().key;
      return firebase.database().ref("/users/" + uid + "/createdApps/" + appKey).set(true).then(function() {
        return {key: appKey, uid: uid};
      });
    }).then(function(result) {
      return firebase.database().ref("/apps/" + result.key).set({
        owner: result.uid,
        maxCalls: 1000
      }).then(function() {
        return result.key;
      });
    }).then(function(key) {
      res.status(201);
      res.json({ok: true, key: key});
    }).catch(function(e) {
      if (e) {console.log(e)}
      if (!res.headersSent) {res.status(500); res.json({ok: false, error: "server_error"})}
    });
  } else if (req.method === "OPTIONS") {
    handleOptionsRequest(req, res, ["POST"]);
  } else {
    send405(res);
  }
});

exports.generatesecret = functions.https.onRequest(function(req, res) {
  if (req.method === "PUT") {
    res.set("Access-Control-Allow-Origin", "*");

    var auth = req.get("Authorization") && req.get("Authorization").split(" ");
    if ((!auth) || auth[0] !== "Firebase" || !auth[1]) {
      res.status(401);
      res.json({ok: false, error: "invalid_auth"});
      return;
    }

    var app = path.basename(path.dirname(req.path));

    firebase.auth().verifyIdToken(auth[1]).catch(function(e) {
      res.status(401);
      res.json({ok: false, error: "invalid_auth"});
      throw e;
    }).then(function(decodedToken) {
      return Promise.all([firebase.database().ref("/apps/" + app + "/owner").once("value"), Promise.resolve(decodedToken.uid)]);
    }).then(function(results) {
      var data = results[0];
      var uid  = results[1];
      if (data.val() === uid) {
        return new Promise(function(resolve, reject) {
          crypto.randomBytes(30, function(err, buf) {
            err ? reject(err) : resolve(buf.toString("base64").replace("/", "-"));
          });
        })
      } else {
        res.status(403);
        res.json({ok: false, error: "forbidden"});
        throw null;
      }
    }).then(function(secret) {
      return Promise.all([secret, firebase.database().ref("/apps/" + app + "/oauth/secret").set(secret)]);
    }).then(function(result) {
      res.json({ok: true, secret: result[0]});
    }).catch(function(e) {
      if (e) {console.log(e)}
      if (!res.headersSent) {res.status(500); res.json({ok: false, error: "server_error"})}
    });
  } else if (req.method === "OPTIONS") {
    handleOptionsRequest(req, res, ["PUT"]);
  } else {
    send405(res);
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
        return firebase.firestore().collection("agendas").where(token.user, "==", true).get();
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(list) {
      var agendas = [];
      list.forEach(function(agenda) {
        agendas.push({name: agenda.data().name, id: agenda.id});
      });
      return agendas;
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

      var agenda = {name: req.body.name, permissions: {}};
      agenda[token.user] = true;
      agenda.permissions[token.user] = {manage: true, complete_tasks: true, edit_tasks: true, edit_tags: true};
      return firebase.firestore().collection("agendas").add(agenda);
    }).then(function(ref) {
      res.status(201);
      res.json({ok: true, id: ref.id});
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

var deleteBatch = function(query, batchSize) {
  return query.get().then(function(data) {
    if (data.size < 1) {
      return 0;
    }

    var batch = firebase.firestore().batch();
    data.forEach(function(doc) {
      batch.delete(doc.ref);
    });

    return batch.commit().then(function() {
      return data.size;
    });
  }).then(function(count) {
    if (count >= batchSize) {
      return $timeout(undefined, 0, false).then(function() {
        return deleteBatch(query, batchSize);
      });
    }
  });
};
var deleteCollection = function(collection) {
  var batchSize = 1000;
  return deleteBatch(collection.limit(batchSize), batchSize);
};

exports.agenda = functions.https.onRequest(function(req, res) {
  var agenda = path.basename(req.path);

  if (req.method === "GET") {
    startApiCall(req, res).then(function(token) {
      if (!token.scopes["agenda-read"]) {
        res.sendStatus(403);
        throw null;
      }

      if (agenda) {
        return Promise.all([token.user, firebase.firestore().collection("agendas").doc(agenda).get()]);
      } else {
        res.status(400);
        res.send("Missing Agenda");
        throw null;
      }
    }).then(function(result) {
      var user = result[0];
      var data = result[1];
      if (data.exists && data.data()[user]) {
        return {name: data.data().name, id: data.id};
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(agenda) {
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

      return Promise.all([token.user, firebase.firestore().collection("agendas").doc(agenda).get()]);
    }).then(function(result) {
      var user = result[0];
      var data = result[1];
      if (data.exists && data.data()[user] && data.data().permissions[user] && data.data().permissions[user].manage) {
        return data.ref.update({
          name: req.body.name || firebase.firestore.FieldValue.delete()
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

      return Promise.all([token.user, firebase.firestore().collection("agendas").doc(agenda).get()]);
    }).then(function(result) {
      var user = result[0];
      var data = result[1];
      if (data.exists && data.data()[user] && data.data().permissions[user] && data.data().permissions[user].manage) {
        var update = {};
        ["name"].filter(function(key) {
          return req.body[key];
        }).forEach(function(key) {
          update[key] = req.body[key];
        });
        return data.ref.update(update);
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

      if (req.body.name && typeof req.body.name !== "string") {
        res.status(400);
        res.send("Invalid Name");
      }

      return Promise.all([token.user, firebase.firestore().collection("agendas").doc(agenda).get()]);
    }).then(function(result) {
      var user = result[0];
      var data = result[1];
      if (data.exists && data.data()[user] && data.data().permissions[user] && data.data().permissions[user].manage) {
        return Promise.all([
          data.ref,
          deleteCollection(data.ref.collection("tasks")),
          deleteCollection(data.ref.collection("tags"))
        ]);
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(result) {
      return result[0].delete();
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
        return Promise.all([token.user, firebase.firestore().collection("agendas").doc(agenda).get()]);
      } else {
        res.status(400);
        res.send("Missing Agenda");
        throw null;
      }
    }).then(function(result) {
      var user = result[0];
      var data = result[1];
      if (data.exists && data.data()[user]) {
        return data.ref.collection("tags").get();
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(data) {
      var categories = [];
      data.forEach(function(child) {
        var category = child.data();
        category.id  = child.id;
        categories.push(category);
      });
      return categories;
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

      if (agenda) {
        return Promise.all([token.user, firebase.firestore().collection("agendas").doc(agenda).get()]);
      } else {
        res.status(400);
        res.send("Missing Agenda");
        throw null;
      }
    }).then(function(result) {
      var user = result[0];
      var data = result[1];
      if (data.exists && data.data()[user] && data.data().permissions[user] && data.data().permissions[user].edit_tags) {
        return data.ref.collection("tags").add({
          name: req.body.name || null,
          color: req.body.color || null
        });
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(ref) {
      res.status(201);
      res.json({ok: true, id: ref.id});
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
        return Promise.all([token.user, firebase.firestore().collection("agendas").doc(agenda).get()]);
      } else if (agenda) {
        res.status(400);
        res.send("Missing Tag");
        throw null;
      } else {
        res.status(400);
        res.send("Missing Agenda");
        throw null;
      }
    }).then(function(result) {
      var user = result[0];
      var data = result[1];
      if (data.exists && data.data()[user]) {
        return data.ref.collection("tags").doc(tag).get();
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(data) {
      if (data.exists) {
        var tagData = data.data();
        tagData.id = data.id;
        return Promise.all([
          Promise.resolve(tagData),
          firebase.firestore().collection("agendas").doc(agenda).collection("tasks").where("tags." + data.id, "==", true).get()
        ]);
      } else {
        res.sendStatus(404);
        throw null;
      }
    }).then(function(results) {
      var tagData = results[0];
      tagData.tasks = [];
      results[1].forEach(function(data) {
        var task = data.data();
        task.id  = data.id;
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

      if (agenda && tag) {
        return Promise.all([token.user, firebase.firestore().collection("agendas").doc(agenda).get()]);
      } else if (agenda) {
        res.status(400);
        res.send("Missing Tag");
        throw null;
      } else {
        res.status(400);
        res.send("Missing Agenda");
        throw null;
      }
    }).then(function(result) {
      var user = result[0];
      var data = result[1];
      if (data.exists && data.data()[user] && data.data().permissions[user] && data.data().permissions[user].edit_tags) {
        return data.ref.collection("tags").doc(tag).get();
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(tag) {
      if (tag.exists) {
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

      if (agenda && tag) {
        return Promise.all([token.user, firebase.firestore().collection("agendas").doc(agenda).get()]);
      } else if (agenda) {
        res.status(400);
        res.send("Missing Tag");
        throw null;
      } else {
        res.status(400);
        res.send("Missing Agenda");
        throw null;
      }
    }).then(function(result) {
      var user = result[0];
      var data = result[1];
      if (data.exists && data.data()[user] && data.data().permissions[user] && data.data().permissions[user].edit_tags) {
        return data.ref.collection("tags").doc(tag).get();
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(tag) {
      if (tag.exists) {
        var update = {};
        ["name", "color"].filter(function(key) {
          return req.body[key] !== undefined;
        }).forEach(function(key) {
          update[key] = req.body[key] || firebase.firestore.FieldValue.delete();
        });
        return tag.ref.update(update);
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
        return Promise.all([token.user, firebase.firestore().collection("agendas").doc(agenda).get()]);
      } else {
        res.status(400);
        res.send("Missing Agenda");
        throw null;
      }
    }).then(function(result) {
      var user = result[0];
      var data = result[1];
      if (data.exists && data.data()[user]) {
        return data.ref.collection("tasks").get();
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(data) {
      var tasks = [];
      data.forEach(function(child) {
        var task = child.data();
        task.id  = child.id;
        if (task.deadline) {
          task.deadline = task.deadline.toJSON();
        }
        if (task.deadlineTime && !task.deadline) {
          delete task.deadlineTime;
        }
        if (task.repeat === "") {
          delete task.repeat;
        }
        if (task.repeatEnds === "") {
          delete task.repeatEnds;
        } else if (task.repeatEnds) {
          task.repeatEnds = task.repeatEnds.toJSON();
        }
        if (task.priority === 0) {
          delete task.priority;
        }
        Object.keys(task).forEach(function(key) {
          if (task[key] === null) {
            delete task[key];
          }
        });
        tasks.push(task);
      });
      return tasks;
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
        ((req.body.priority !== undefined && req.body.priority !== null) && typeof req.body.priority !== "number") ||
        (req.body.notes && typeof req.body.notes !== "string") ||
        !(req.body.name || req.body.deadline || req.body.deadlineTime || req.body.repeat || req.body.repeatEnds || req.body.tags || req.body.priority || req.body.notes)
      ) {
        res.sendStatus(400);
        throw null;
      }

      return Promise.all([token.user, firebase.firestore().collection("agendas").doc(agenda).get()]);
    }).then(function(result) {
      var user = result[0];
      var data = result[1];
      if (data.exists && data.data()[user] && data.data().permissions[user] && data.data().permissions[user].edit_tasks) {
        if (req.body.tags) {
          var tags = {};
          req.body.tags.forEach(function(tag) {
            tags[tag] = true;
          });
          return {ref: data.ref.collection("tasks"), tags: tags};
        } else {
          return {ref: data.ref.collection("tasks")};
        }
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(result) {
      var taskRef = result.ref;
      var tags    = result.tags;

      return taskRef.add({
        name: req.body.name || null,
        completed: !!req.body.completed,
        deadline: req.body.deadline ? new Date(req.body.deadline) : null,
        deadlineTime: req.body.deadlineTime || null,
        repeat: req.body.repeat || null,
        repeatEnds: req.body.repeatEnds ? new Date(req.body.repeatEnds) : null,
        tags: tags || null,
        priority: req.body.priority || null,
        notes: req.body.notes || null
      });
    }).then(function(ref) {
      res.status(201);
      res.json({ok: true, id: ref.id});
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
        return Promise.all([token.user, firebase.firestore().collection("agendas").doc(agenda).get()]);
      } else if (agenda) {
        res.status(400);
        res.send("Missing Task");
        throw null;
      } else {
        res.status(400);
        res.send("Missing Agenda");
        throw null;
      }
    }).then(function(result) {
      var user = result[0];
      var data = result[1];
      if (data.exists && data.data()[user]) {
        return data.ref.collection("tasks").doc(task).get();
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(data) {
      if (data.exists) {
        var taskData = data.data();
        taskData.id = data.id;

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

        Object.keys(taskData).forEach(function(key) {
          if (taskData[key] === null) {
            delete taskData[key];
          }
        });

        if (taskData.tags) {
          return Promise.all(Object.keys(taskData.tags).map(function(tag) {
            return firebase.firestore().collection("agendas").doc(agenda).collection("tags").doc(tag).get();
          })).then(function(tags) {
            taskData.tags = tags.filter(function(tag) {
              return tag.exists;
            }).map(function(data) {
              var tag = data.data();
              tag.id = data.id;
              return tag;
            })

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
        ((req.body.priority !== undefined && req.body.priority !== null) && typeof req.body.priority !== "number") ||
        (req.body.notes && typeof req.body.notes !== "string") ||
        !(req.body.name || req.body.deadline || req.body.deadlineTime || req.body.repeat || req.body.repeatEnds || req.body.tags || req.body.priority || req.body.notes)
      ) {
        res.sendStatus(400);
        throw null;
      }

      if (agenda && task) {
        return Promise.all([token.user, firebase.firestore().collection("agendas").doc(agenda).get()]);
      } else if (agenda) {
        res.status(400);
        res.send("Missing Task");
        throw null;
      } else {
        res.status(400);
        res.send("Missing Agenda");
        throw null;
      }
    }).then(function(result) {
      var user = result[0];
      var data = result[1];
      if (data.exists && data.data()[user] && data.data().permissions[user] && data.data().permissions[user].edit_tasks) {
        return data.ref.collection("tasks").doc(task).get();
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(task) {
      if (task.exists) {
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
          completed: !!req.body.completed,
          deadline: req.body.deadline ? new Date(req.body.deadline) : null,
          deadlineTime: req.body.deadlineTime || null,
          repeat: req.body.repeat || null,
          repeatEnds: req.body.repeatEnds ? new Date(req.body.repeatEnds) : null,
          tags: tags || null,
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
        ((req.body.priority !== undefined && req.body.priority !== null) && typeof req.body.priority !== "number") ||
        (req.body.notes && typeof req.body.notes !== "string")
      ) {
        res.sendStatus(400);
        throw null;
      }

      if (agenda && task) {
        return Promise.all([token.user, firebase.firestore().collection("agendas").doc(agenda).get()]);
      } else if (agenda) {
        res.status(400);
        res.send("Missing Task");
        throw null;
      } else {
        res.status(400);
        res.send("Missing Agenda");
        throw null;
      }
    }).then(function(result) {
      var user = result[0];
      var data = result[1];
      if (data.exists && data.data()[user] && data.data().permissions[user] && data.data().permissions[user].edit_tasks) {
        return data.ref.collection("tasks").doc(task).get();
      } else {
        res.sendStatus(403);
        throw null;
      }
    }).then(function(task) {
      if (task.exists) {
        var update = {};
        ["name", "deadline", "deadlineTime", "repeat", "repeatEnds", "tags", "priority", "notes", "completed"].filter(function(key) {
          return req.body[key] !== undefined;
        }).forEach(function(key) {
          if (key === "tags") {
            if (req.body.tags && req.body.tags.length > 0) {
              var tags = {};
              req.body.tags.forEach(function(tag) {
                tags[tag] = true;
              });
              update.tags = tags;
            } else {
              update.tags = firebase.firestore.FieldValue.delete();
            }
          } else if (key === "completed") {
            update.completed = !!req.body.completed;
          } else if (key === "deadline" || key === "repeatEnds") {
            if (req.body[key]) {
              update[key] = new Date(req.body[key]);
            } else {
              update[key] = firebase.firestore.FieldValue.delete();
            }
          } else {
            update[key] = req.body[key] || firebase.firestore.FieldValue.delete();
          }
        });
        return task.ref.update(update);
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
        return Promise.all([
          firebase.database().ref("/users/" + token.uid + "/apps/" + app + "/token/token").once("value"),
          firebase.database().ref("/users/" + token.uid + "/apps/" + app + "/code").once("value"),
          firebase.database().ref("/users/" + token.uid + "/apps/" + app + "/refresh").once("value")
        ]);
      }).then(function(result) {
        var token = result[0];
        var code  = result[1];
        var refre = result[2];
        return Promise.all([
          token.ref.parent.parent.remove(),
          token.exists() && firebase.database().ref("/tokens/" + token.val()).remove(),
          code.exists() && firebase.database().ref("/codes/" + code.val()).remove(),
          refre.exists() && firebase.database().ref("/refresh/" + refre.val()).remove()
        ]);
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

exports.setMaxApps = functions.auth.user().onCreate(function(event) {
  return firebase.database("/users/" + event.data.uid + "/maxApps").set(10);
});

exports.setMaxApps2 = functions.database.ref("/users/{user}/isDeveloper").onWrite(function(event) {
  if (event.data.val()) {
    return event.data.adminRef.parent.child("maxApps").once("value").then(function(value) {
      if (!value.exists()) {
        return value.ref.set(10);
      }
    })
  }
});
