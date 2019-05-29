function addSetting() {
  $("#addSettingModal").modal();
}

function confirmAddSetting() {
  var _csrftoken = $("#csrftoken").val();

  var _url = window.location.pathname;

  var _name = $("#setting_name").val();
  var _type = $("#setting_type").val();
  var _value = $("#setting_value").val();

  var data = {
    csrftoken: _csrftoken,
    action: 'add',
    name: _name,
    type: _type,
    value: _value,
  };
  sendPostRequest(data, _url, _url, false);
}

function changeDebugAdmin() {
  var _csrftoken = $("#csrftoken").val();
  var _value = $("#admin_debug_check").is(':checked');

  var _url = '/settings/admin';

  var data = {
    csrftoken: _csrftoken,
    action: 'debug',
    debughttp: _value,
  };
  sendPostRequest(data, _url, '', false);
}
