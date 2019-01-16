function sendPostRequest(req_data, req_url) {
  $.ajax({
    url: req_url,
    dataType: 'json',
    type: 'POST',
    contentType: 'application/json',
    data: JSON.stringify(req_data),
    processData: false,
    success: function(data, textStatus, jQxhr){
      console.log('OK');
      window.location.replace("dashboard");
    },
    error: function(jqXhr, textStatus, errorThrown){
      var _clientmsg = 'Client: ' + errorThrown;
      var _serverJSON = $.parseJSON(jqXhr.responseText);
      var _servermsg = 'Server: ' + _serverJSON.message;
      $("#errorModalMessageClient").text(_clientmsg);
      console.log(_clientmsg);
      $("#errorModalMessageServer").text(_servermsg);
      $("#errorModal").modal();
    }
  });
}

function sendLogin() {
  var _user = $("#login_user").val();
  var _password = $("#login_password").val();
  
  var _url = '/login';
  var data = {
      username: _user,
      password: _password
  };
  sendPostRequest(data, _url, false);
}

$("#login_password").keyup(function(event) {
  if (event.keyCode === 13) {
      $("#login_button").click();
  }
});
