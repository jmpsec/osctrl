function genericLinkAction(_type, _action) {
  var _csrftoken = $("#csrftoken").val();
  var _url = "/expiration/" + window.location.pathname.split("/").pop();
  var data = {
    csrftoken: _csrftoken,
    type: _type,
    action: _action,
  };
  sendPostRequest(data, _url, window.location.pathname, false);
}

function extendEnrollLink() {
  genericLinkAction("enroll", "extend");
}

function expireEnrollLink() {
  genericLinkAction("enroll", "expire");
}

function rotateEnrollLink() {
  genericLinkAction("enroll", "rotate");
}

function notexpireEnrollLink() {
  genericLinkAction("enroll", "notexpire");
}

function extendRemoveLink() {
  genericLinkAction("remove", "extend");
}

function expireRemoveLink() {
  genericLinkAction("remove", "expire");
}

function rotateRemoveLink() {
  genericLinkAction("remove", "rotate");
}

function notexpireRemoveLink() {
  genericLinkAction("remove", "notexpire");
}

function confirmUploadCertificate() {
  $("#certificate_action").click(function () {
    $("#certificateModal").modal("hide");
    uploadCertificate();
  });
  $("#certificateModal").modal();
}

function uploadCertificate() {
  var _csrftoken = $("#csrftoken").val();
  var _blob = $("#certificate").data("CodeMirrorInstance");
  var _certificate = _blob.getValue();

  var _url = window.location.pathname;

  var data = {
    csrftoken: _csrftoken,
    action: "enroll_certificate",
    certificate: btoa(_certificate),
  };
  sendPostRequest(data, _url, window.location.pathname, false);
}

function saveDebPackage() {
  var _package = $("#deb-package-value").val();
  savePackage(_package, "package_deb");
}

function saveRpmPackage() {
  var _package = $("#rpm-package-value").val();
  savePackage(_package, "package_rpm");
}

function savePkgPackage() {
  var _package = $("#pkg-package-value").val();
  savePackage(_package, "package_pkg");
}

function saveMsiPackage() {
  var _package = $("#msi-package-value").val();
  savePackage(_package, "package_msi");
}

function savePackage(_package, _action) {
  var _csrftoken = $("#csrftoken").val();

  var _url = window.location.pathname;

  var data = {
    csrftoken: _csrftoken,
    action: _action,
    packageurl: _package,
  };
  sendPostRequest(data, _url, window.location.pathname, false);
}
