function statsRefresh(_target, _identifier) {
  $.ajax({
    url: '/json/stats/' + _target + '/' + _identifier,
    dataType: 'json',
    type: 'GET',
    contentType: 'application/json',
    success: function (data, textStatus, jQxhr) {
      $('.stats-' + _target + '-' + _identifier + '-active').text(data.active);
      $('.stats-' + _target + '-' + _identifier + '-inactive').text(data.inactive);
      $('.stats-' + _target + '-' + _identifier + '-total').text(data.total);
    },
    error: function (jqXhr, textStatus, errorThrown) {
      var _clientmsg = 'Client: ' + errorThrown;
      var _serverJSON = $.parseJSON(jqXhr.responseText);
      var _servermsg = 'Server: ' + _serverJSON.message;
      console.log('Error getting stats...');
      console.log(_clientmsg);
      console.log(_servermsg);
    }
  });
}

function beginStats() {
  var _stats = ['environment'];
  for (var i = 0; i < _stats.length; i++) {
    $('input[type="hidden"].stats-' + _stats[i] + '-value').each(function () {
      statsRefresh(_stats[i], $(this).val());
    });
  }
}
