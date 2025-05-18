// JavaScript for authentication pages
document.addEventListener('DOMContentLoaded', function() {
    // Password confirmation validation
    const passwordField = document.getElementById('password');
    const confirmPasswordField = document.getElementById('confirm_password');
    
    if (passwordField && confirmPasswordField) {
        confirmPasswordField.addEventListener('input', function() {
            if (passwordField.value !== confirmPasswordField.value) {
                confirmPasswordField.setCustomValidity("Passwords don't match");
            } else {
                confirmPasswordField.setCustomValidity('');
            }
        });
        
        passwordField.addEventListener('input', function() {
            if (confirmPasswordField.value && passwordField.value !== confirmPasswordField.value) {
                confirmPasswordField.setCustomValidity("Passwords don't match");
            } else {
                confirmPasswordField.setCustomValidity('');
            }
        });
    }
    
    // Auto-focus on token input for MFA verification
    const tokenInput = document.getElementById('token');
    if (tokenInput) {
        tokenInput.focus();
    }
    
    // Flash message auto-dismiss
    const flashMessages = document.querySelectorAll('.flash-message');
    if (flashMessages.length > 0) {
        setTimeout(function() {
            flashMessages.forEach(function(message) {
                message.style.opacity = '0';
                setTimeout(function() {
                    message.style.display = 'none';
                }, 500);
            });
        }, 5000);
    }
});
