// static/js/scripts.js
document.addEventListener('DOMContentLoaded', function() {
    const allAlerts = document.querySelectorAll('.alert');
    allAlerts.forEach(function(alert) {
        if (!alert.querySelector('.close-btn')) {
            const closeButton = document.createElement('button');
            closeButton.innerText = '×';
            closeButton.className = 'close-btn';
            closeButton.addEventListener('click', function() {
                alert.style.opacity = '0';
                setTimeout(() => {
                    alert.style.display = 'none';
                }, 500);
            });
            alert.appendChild(closeButton);
        }
    });

    const fileInput = document.getElementById('file');
    const filenameDisplay = document.getElementById('filename-display');
    if (fileInput && filenameDisplay) {
        fileInput.addEventListener('change', function() {
            if (this.files.length > 0) {
                filenameDisplay.textContent = `Selected file: ${this.files[0].name}`;
            } else {
                filenameDisplay.textContent = '';
            }
        });
    }
});