function saveConfiguration() {
  var _csrftoken = $("#csrftoken").val();
  var _editor = $('#conf').data('CodeMirrorInstance');
  var _configuration = _editor.getValue();

  var _url = window.location.pathname;

  var data = {
    csrftoken: _csrftoken,
    configuration: btoa(_configuration),
  };
  sendPostRequest(data, _url, '', true);
}

function lineCharPosition(_pos) {
  var line = 0;
  var ttl = 0;
  $('.CodeMirror-line').each(function () {
    console.log('Line ' + line);
    var l = $(this).text().length;
    ttl += l;
    if (ttl >= _pos) {
      return false;
    }
    line++;
  });
  return 'line ' + line;
}

function genericLinkAction(_type, _action) {
  var _csrftoken = $("#csrftoken").val();
  var _url = '/expiration/' + window.location.pathname.split('/').pop();
  var data = {
    csrftoken: _csrftoken,
    type: _type,
    action: _action,
  };
  sendPostRequest(data, _url, window.location.pathname, false);
}

function extendEnrollLink() {
  genericLinkAction('enroll', 'extend');
}

function expireEnrollLink() {
  genericLinkAction('enroll', 'expire');
}

function extendRemoveLink() {
  genericLinkAction('remove', 'extend');
}

function expireRemoveLink() {
  genericLinkAction('remove', 'expire');
}
