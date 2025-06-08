// validation.js

// SweetAlert2 toast helper
function showToast(message, icon='error') {
  Swal.fire({
    icon: icon,
    title: message,
    toast: true,
    position: 'top-end',
    showConfirmButton: false,
    timer: 3000,
    timerProgressBar: true
  });
}

// Validate converter form before submitting
function validateForm() {
  const fileInput = document.getElementById('file');
  const convType = document.getElementById('conversion_type').value;
  if (!fileInput.value) {
    showToast('Please choose a PDF file to convert.');
    return false;
  }
  if (!convType) {
    showToast('Please select a conversion type.');
    return false;
  }
  return true;
}

// Signup form validation
function validateSignupForm() {
  const username = document.getElementById('username').value.trim();
  const email = document.getElementById('email').value.trim();
  const password = document.getElementById('password').value;
  const confirm = document.getElementById('confirm_password').value;

  if (username.length < 3) {
    showToast('Username must be at least 3 characters long.');
    return false;
  }
  // Basic email regex
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!re.test(email)) {
    showToast('Please enter a valid email address.');
    return false;
  }
  if (password.length < 6) {
    showToast('Password must be at least 6 characters long.');
    return false;
  }
  if (password !== confirm) {
    showToast('Passwords do not match.');
    return false;
  }
  return true;
}

// Login form validation
function validateLoginForm() {
  const id = document.getElementById('email_or_username').value.trim();
  const p = document.getElementById('password').value;
  if (!id) {
    showToast('Please enter your email or username.');
    return false;
  }
  if (!p) {
    showToast('Please enter your password.');
    return false;
  }
  return true;
}

// Email validation (for reset request)
function validateEmailForm() {
  const email = document.getElementById('email').value.trim();
  const re = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
  if (!re.test(email)) {
    showToast('Please enter a valid email address.');
    return false;
  }
  return true;
}

// Reset password form validation
function validateResetForm() {
  const password = document.getElementById('password').value;
  const confirm = document.getElementById('confirm_password').value;
  if (password.length < 6) {
    showToast('Password must be at least 6 characters long.');
    return false;
  }
  if (password !== confirm) {
    showToast('Passwords do not match.');
    return false;
  }
  return true;
}
