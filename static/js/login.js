document.getElementById('loginForm').addEventListener('submit', function(event) {
    event.preventDefault(); // Prevent the form from submitting the traditional way

    const username = document.getElementById('username').value;
    const password = document.getElementById('password').value;

    // Prepare the data to send as JSON
    const data = {
        username: username,
        password: password
    };

    fetch('http://127.0.0.1:5000/admin/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(data)
    })
    .then(response => response.json())
    .then(data => {
        // Display the response message from the server
        document.getElementById('responseMessage').textContent = data.message;

        if (data.message === "Login successful") {
            // Redirect to the dashboard after successful login
            window.location.href = "/dashboard"; // Adjust based on your route
        }
    })
    .catch(error => {
        console.error('Error:', error);
        document.getElementById('responseMessage').textContent = "An error occurred.";
    });
});
