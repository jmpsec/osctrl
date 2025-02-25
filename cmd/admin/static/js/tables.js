// Function to pause/refresh the table fetching data
function changeTableRefresh(value_id, button_id) {
  if (document.getElementById(value_id).value === 'yes') {
    document.getElementById(value_id).value = 'no';
    document.getElementById(button_id).innerHTML = '<i class="fas fa-play"></i>';
  } else {
    document.getElementById(value_id).value = 'yes';
    document.getElementById(button_id).innerHTML = '<i class="fas fa-pause"></i>';
  }
  return;
}

// Function to refresh table when clicked
function refreshTableNow(table_id) {
  var table = $('#' + table_id).DataTable();
  table.ajax.reload();
  return;
}
