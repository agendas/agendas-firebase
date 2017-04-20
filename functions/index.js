var functions = require('firebase-functions');

exports.processAgenda = functions.database.ref("/permissions/{agenda}/{user}").onWrite(event => {
  if (event.data.previous.exists() && !event.data.current.exists()) {
    // Delete an agenda from the user's hierarchy.
    var hierarchy = event.data.adminRef.root.child("users").child(event.params.user).child("agendas");

    hierarchy.once("value").then(function(data) {
      if (data.exists()) {
        hierarchy.child(event.params.agenda).remove();
        data.forEach(function(agenda) {
          if (agenda.key !== event.params.agenda) {
            return agenda.forEach(function(child) {
              if (child.key === event.params.agenda) {
                child.ref.remove();

                if (data.child(event.params.agenda).exists()) {
                  data.child(event.params.agenda).forEach(function(childOfRemoved) {
                    agenda.ref.child(childOfRemoved.key).set(true);
                  });
                }

                return true;
              }
            });
          }
        });
      }
    });
  } else if (event.data.current.exists() && !event.data.previous.exists()) {
    // Add an agenda to the user's hierarchy.
    var hierarchy = event.data.adminRef.root.child("users").child(event.params.user).child("agendas");

    hierarchy.child("root").child(event.params.agenda).set(true);
    hierarchy.child(event.params.agenda).set({});
  }
});
