document.addEventListener('DOMContentLoaded', function() {
    const passwordInput = document.getElementById('passwordInput');
    const strengthBar = document.getElementById('strengthBar');
    const strengthText = document.getElementById('strengthText');

    if (!passwordInput || !strengthBar || !strengthText) return;

    passwordInput.addEventListener('input', function() {
        const password = this.value;
        const result = checkPasswordStrength(password);
        
        strengthBar.style.width = result.percentage + '%';
        strengthBar.className = 'progress-bar ' + result.colorClass;
        strengthText.textContent = result.text;
        strengthText.className = result.textClass;
    });

    function checkPasswordStrength(password) {
        let strength = 0;
        const checks = {
            length: password.length >= 12,
            lowercase: /[a-z]/.test(password),
            uppercase: /[A-Z]/.test(password),
            numbers: /\d/.test(password),
            special: /[^a-zA-Z\d]/.test(password),
            extraLength: password.length >= 16
        };

        if (checks.length) strength += 20;
        if (checks.lowercase) strength += 15;
        if (checks.uppercase) strength += 15;
        if (checks.numbers) strength += 15;
        if (checks.special) strength += 20;
        if (checks.extraLength) strength += 15;

        let result = {
            percentage: strength,
            colorClass: 'bg-danger',
            text: 'Very Weak',
            textClass: 'text-danger'
        };

        if (strength >= 85) {
            result = { percentage: 100, colorClass: 'bg-success', text: 'Strong', textClass: 'text-success' };
        } else if (strength >= 65) {
            result = { percentage: 75, colorClass: 'bg-info', text: 'Good', textClass: 'text-info' };
        } else if (strength >= 45) {
            result = { percentage: 50, colorClass: 'bg-warning', text: 'Fair', textClass: 'text-warning' };
        } else if (strength >= 25) {
            result = { percentage: 25, colorClass: 'bg-danger', text: 'Weak', textClass: 'text-danger' };
        }

        // Build requirements list
        let missing = [];
        if (!checks.length) missing.push('12+ characters');
        if (!checks.lowercase) missing.push('lowercase');
        if (!checks.uppercase) missing.push('uppercase');
        if (!checks.numbers) missing.push('number');
        if (!checks.special) missing.push('special character');

        if (missing.length > 0 && password.length > 0) {
            result.text += ' - Missing: ' + missing.join(', ');
        }

        return result;
    }
});
