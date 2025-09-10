function createTag() {
  $("#modal_title_tag").text("Create new Tag");
  $("#modal_button_tag").text("Create");
  $("#modal_button_tag").click(function () {
    $("#createEditTagModal").modal("hide");
    confirmCreateTag();
  });
  generateColor();
  $("#tag_name").val("");
  $("#tag_description").val("");
  $("#tag_icon").val("");
  $("#tag_env").val("");
  $("#tag_custom").val("");
  $("#createEditTagModal").modal();
}

function editTag(_name) {
  $("#modal_title_tag").text("Edit Tag " + _name);
  $("#modal_button_tag").text("Update");
  $("#modal_button_tag").click(function () {
    $("#createEditTagModal").modal("hide");
    confirmEditTag();
  });
  $("#tag_name").val(_name);
  $("#tag_description").val($("#tag_desc_" + _name).val());
  $("#tag_color").val($("#tag_color_" + _name).val());
  $("#tag_icon").val($("#tag_icon_" + _name).val());
  $("#tag_env")
    .val($("#tag_env_" + _name).val())
    .change();
  $("#tag_type")
    .val($("#tag_type_" + _name).val())
    .change();
  $("#createEditTagModal").modal();
}

function confirmCreateTag() {
  var _csrftoken = $("#csrftoken").val();
  var _url = window.location.pathname;
  var _name = $("#tag_name").val();
  var _description = $("#tag_description").val();
  var _color = $("#tag_color").val();
  var _icon = $("#tag_icon").val();
  var _env = $("#tag_env").val();
  var _custom = $("#tag_custom").val();
  var _tagtype = parseInt($("#tag_type").val());
  var data = {
    csrftoken: _csrftoken,
    action: "add",
    name: _name,
    description: _description,
    color: _color,
    icon: _icon,
    environment: _env,
    tagtype: _tagtype,
    custom: _custom,
  };
  sendPostRequest(data, _url, _url, false);
}

function confirmEditTag() {
  var _csrftoken = $("#csrftoken").val();
  var _url = window.location.pathname;
  var _name = $("#tag_name").val();
  var _description = $("#tag_description").val();
  var _color = $("#tag_color").val();
  var _icon = $("#tag_icon").val();
  var _env = $("#tag_env").val();
  var _tagtype = parseInt($("#tag_type").val());
  var _custom = $("#tag_custom").val();
  var data = {
    csrftoken: _csrftoken,
    action: "edit",
    name: _name,
    description: _description,
    color: _color,
    icon: _icon,
    environment: _env,
    tagtype: _tagtype,
    custom: _custom,
  };
  sendPostRequest(data, _url, _url, false);
}

function confirmDeleteTag(_tag) {
  var modal_message = "Are you sure you want to delete the tag " + _tag + "?";
  $("#confirmModalMessage").text(modal_message);
  $("#confirm_action").click(function () {
    $("#confirmModal").modal("hide");
    deleteTag(_tag);
  });
  $("#confirmModal").modal();
}

function deleteTag(_tag) {
  var _csrftoken = $("#csrftoken").val();
  var _url = window.location.pathname;
  var _env = $("#tag_env_" + _tag).val();
  var data = {
    csrftoken: _csrftoken,
    action: "remove",
    name: _tag,
    environment: _env,
  };
  sendPostRequest(data, _url, _url, false);
}

function generateColor() {
  var randomColor = "#" + Math.random().toString(16).substr(2, 6);
  $("#tag_color").val(randomColor);
  $("#show_color").css("background-color", randomColor);
}
