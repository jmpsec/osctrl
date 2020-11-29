function statsRefresh(_target, _uuid) {
  $.ajax({
    url: '/json/stats/' + _target + '/' + _uuid,
    dataType: 'json',
    type: 'GET',
    contentType: 'application/json',
    success: function(data, textStatus, jQxhr){
      $('.stats-' + _target + '-' + _uuid + '-active').text(data.active);
      $('.stats-' + _target + '-' + _uuid + '-inactive').text(data.inactive);
      $('.stats-' + _target + '-' + _uuid + '-total').text(data.total);
      //console.log('Active: ' + data.active);
      //console.log('Inactive: ' + data.inactive);
      //console.log('Total: ' + data.total);
    },
    error: function(jqXhr, textStatus, errorThrown){
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
  var _stats = ['environment', 'platform'];
  for (var i = 0; i<_stats.length; i++) {
    //console.log('Doing ' + _stats[i]);
    $('input[type="hidden"].stats-' + _stats[i] + '-value').each(function () {
      statsRefresh(_stats[i], $(this).val());
    });
  }
}
