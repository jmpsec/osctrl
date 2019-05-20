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
    //console.log('Line ' + line);
    var l = $(this).text().length;
    ttl += l;
    if (ttl >= _pos) {
      return 'line ' + line;
    }
    line++;
  });
  return 'line ' + line;
}
