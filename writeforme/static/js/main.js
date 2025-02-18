// Scroll chat messages to bottom
function scrollToBottom() {
    const messages = document.getElementById('messages');
    if (messages) {
        messages.scrollTop = messages.scrollHeight;
    }
}

// Call on page load
document.addEventListener('DOMContentLoaded', function() {
    scrollToBottom();
});

// Preview file uploads
function previewFile(input) {
    if (input.files && input.files[0]) {
        const reader = new FileReader();
        reader.onload = function(e) {
            const preview = document.getElementById('file-preview');
            if (preview) {
                preview.src = e.target.result;
            }
        };
        reader.readAsDataURL(input.files[0]);
    }
}

// Auto-refresh for status updates (every 30 seconds)
function autoRefresh() {
    if (document.querySelector('.dashboard')) {
        setTimeout(function() {
            location.reload();
        }, 30000);
    }
}

autoRefresh(); 