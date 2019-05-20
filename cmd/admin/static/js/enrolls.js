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
