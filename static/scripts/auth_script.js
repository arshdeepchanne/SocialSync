document.getElementById("login-form").addEventListener("submit", function(event) {
    event.preventDefault(); // Prevent default form submission

    // Get form values
    var email = document.getElementById("email").value;
    var password = document.getElementById("password").value;

    // Here you can perform any actions with the form values, such as sending them to a server for authentication

    // For demonstration purposes, just log the values to the console
    console.log("Email:", email);
    console.log("Password:", password);
  });