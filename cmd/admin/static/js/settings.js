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

function confirmDeleteSetting(_name) {
  var modal_message = 'Are you sure you want to delete the setting ' + _name + '?';
  $("#confirmModalMessage").text(modal_message);
  $('#confirm_action').click(function () {
    $('#confirmModal').modal('hide');
    deleteSetting(_name);
  });
  $("#confirmModal").modal();
}

function deleteSetting(_name) {
  var _csrftoken = $("#csrftoken").val();

  var _url = window.location.pathname;

  var _type = $("#setting_type").val();
  var _value = $("#setting_value").val();

  var data = {
    csrftoken: _csrftoken,
    action: 'delete',
    name: _name,
  };
  sendPostRequest(data, _url, _url, false);
}

function changeBooleanSetting(_name) {
  var _csrftoken = $("#csrftoken").val();
  var _value = $("#" + _name).is(':checked');

  var _url = window.location.pathname;

  var data = {
    csrftoken: _csrftoken,
    action: 'change',
    name: _name,
    type: 'boolean',
    boolean: _value,
  };
  sendPostRequest(data, _url, '', false);
}

function changeDebug(_name, service) {
  var _csrftoken = $("#csrftoken").val();
  var _value = $("#" + _name + '_' + service).is(':checked');

  var _url = '/settings/' + service;

  var data = {
    csrftoken: _csrftoken,
    action: 'change',
    name: _name,
    type: 'boolean',
    boolean: _value,
  };
  sendPostRequest(data, _url, '', false);
}
