var OpenSSLExpModule = null;  // Global application object.
var statusText = 'NO-STATUS';

// Indicate load success.
function moduleDidLoad() {
    OpenSSLExpModule = document.getElementById('openssl_exp_extension');
    updateStatus('SUCCESS');
    // Send a message to the NaCl module.
    OpenSSLExpModule.postMessage('hello');
}

// The 'message' event handler.  This handler is fired when the NaCl module
// posts a message to the browser by calling PPB_Messaging.PostMessage()
// (in C) or pp::Instance.PostMessage() (in C++).  This implementation
// simply displays the content of the message in an alert panel.
function handleMessage(message_event) {
    updateMessage(message_event.data);
}

// If the page loads before the Native Client module loads, then set the
// status message indicating that the module is still loading.  Otherwise,
// do not change the status message.
function pageDidLoad() {
    if (OpenSSLExpModule == null) {
        updateStatus('LOADING...');
    } else {
        // It's possible that the Native Client module onload event fired
        // before the page's onload event.  In this case, the status message
        // will reflect 'SUCCESS', but won't be displayed.  This call will
        // display the current message.
        updateStatus();
    }
}

function updateStatus(opt_message) {
    if (opt_message) {
        statusText = opt_message;
    }
    var statusField = document.getElementById('status_field');
    if (statusField) {
        statusField.innerHTML = statusText;
    }
}

function updateMessage(message) {
    var messageField = document.getElementById('message_field');
    if (messageField) {
        messageField.innerHTML = message;
    }
}