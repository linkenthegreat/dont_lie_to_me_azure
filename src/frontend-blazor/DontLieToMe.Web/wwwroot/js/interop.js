window.scrollToBottom = function(element) {
    if (element) {
        element.scrollTop = element.scrollHeight;
    }
};

window.openUrl = function(url) {
    window.open(url, '_blank');
};

window.triggerFileInput = function(inputId) {
    var el = document.getElementById(inputId);
    if (el) el.click();
};

window.setupPasteHandler = function(dotNetRef) {
    document.addEventListener('paste', function(e) {
        var items = e.clipboardData?.items;
        if (!items) return;
        for (var i = 0; i < items.length; i++) {
            if (items[i].type.startsWith('image/')) {
                var blob = items[i].getAsFile();
                var reader = new FileReader();
                reader.onloadend = function() {
                    dotNetRef.invokeMethodAsync('OnImagePasted', reader.result);
                };
                reader.readAsDataURL(blob);
                e.preventDefault();
                break;
            }
        }
    });
};
