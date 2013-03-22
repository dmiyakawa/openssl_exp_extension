var listener = document.getElementById('listener');
listener.addEventListener('load', moduleDidLoad, true);
listener.addEventListener('message', handleMessage, true);