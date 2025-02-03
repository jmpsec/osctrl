function sendGetRequest(req_url, _modal, _callback) {
  $.ajax({
    url: req_url,
    dataType: 'json',
    type: 'GET',
    contentType: 'application/json',
    success: function (data, textStatus, jQxhr) {
      console.log('OK');
      console.log(data);
      if (_modal) {
        $("#successModalMessage").text(data.message);
        $("#successModal").modal();
      }
      if (_callback) {
        _callback(data);
      }
    },
    error: function (jqXhr, textStatus, errorThrown) {
      var _clientmsg = "Client: " + errorThrown;
      var _serverJSON = $.parseJSON(jqXhr.responseText);
      var _servermsg = 'Server: ' + _serverJSON.message;
      $("#errorModalMessageClient").text(_clientmsg);
      console.log(_clientmsg);
      $("#errorModalMessageServer").text(_servermsg);
      $("#errorModal").modal();
    }
  });
}

function sendPostRequest(req_data, req_url, _redir, _modal, _callback) {
  $.ajax({
    url: req_url,
    dataType: "json",
    type: "POST",
    contentType: "application/json",
    data: JSON.stringify(req_data),
    processData: false,
    success: function (data, textStatus, jQxhr) {
      console.log("OK");
      console.log(data);
      if (_modal) {
        $("#successModalMessage").text(data.message);
        $("#successModal").modal();
      }
      if (_redir !== "") {
        window.location.replace(_redir);
      }
      if (_callback) {
        _callback(data);
      }
    },
    error: function (jqXhr, textStatus, errorThrown) {
      var _clientmsg = "Client: " + errorThrown;
      var _serverJSON = $.parseJSON(jqXhr.responseText);
      var _servermsg = "Server: " + _serverJSON.message;
      $("#errorModalMessageClient").text(_clientmsg);
      console.log(_clientmsg);
      $("#errorModalMessageServer").text(_servermsg);
      $("#errorModal").modal();
    }
  });
}
