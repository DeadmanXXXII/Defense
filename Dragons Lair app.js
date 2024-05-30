// Encode/Decode functionality
const Base64 = {
    encode: (str) => btoa(str),
    decode: (str) => atob(str),
};

// Function to add user (mocked for demonstration)
const addUser = (username, role) => {
    console.log(`User '${username}' added with role '${role}'`);
};

// Function to add super root account (mocked for demonstration)
const addSuperRootAccount = (username, password) => {
    console.log(`Super root account '${username}' added with password '${Base64.encode(password)}'`);
};

// Event listener for Add User form
document.getElementById('addUserForm').addEventListener('submit', (event) => {
    event.preventDefault();
    const username = event.target.username.value;
    const role = event.target.role.value;
    addUser(username, role);
    alert(`User '${username}' added with role '${role}'`);
});

// Event listener for Add Super Root form
document.getElementById('addSuperRootForm').addEventListener('submit', (event) => {
    event.preventDefault();
    const username = event.target.superUsername.value;
    const password = event.target.superPassword.value;
    addSuperRootAccount(username, password);
    alert(`Super root account '${username}' added`);
});