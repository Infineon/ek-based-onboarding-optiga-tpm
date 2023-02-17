/**
 * MIT License
 *
 * Copyright (c) 2020 Infineon Technologies AG
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE
 */

window.onload = function() {
  console.log("website loaded");
  console.log(users);
  console.log(devices);
  fCheckBrowser();
  fWebSocket_init();
  fTableInit();
  fGetUsername();
  fCheckboxInit();
}

function fGetUsername() {
  fWebApi('GET', 'get-username', null,function (json) {
    if (json.status === RESP_OK) {
      console.log("logged in as: " + json.data);
    } else {
      console.log("failed to fetch username");
    }
  });
}

function fSignOut() {
  fWebApi('GET', 'signout', null,function (json) {
    if (json.status === RESP_OK) {
      location.href = '/entry';
    }
  });
}

function fTableInit() {
  devices.forEach(function(item, index) {
    fTableDeviceAddRow(item.name, item.hmacPriv, item.sharedKey);
  });
  whitelist.forEach(function(item, index) {
    fTableWLAddRow(item.pk);
  });
}

function fTableDeviceAddRow(did, hmac, aes) {
  let markup = "<tr style='word-break: break-word;'><td><input type='checkbox' name='tr-checkbox'></td><td>" + did + "</td><td>" + hmac + "</td><td>" + aes + "</td></tr>";
  $("#idTableDevice").append(markup);
}

function fTableWLAddRow(pk) {
  let markup = "<tr style='word-break: break-word;'><td><input type='checkbox' name='tr-checkbox'></td><td>" + pk + "</td></tr>";
  $("#idTableWL").append(markup);
}

function fTableUpdateRowAes(did, aes) {
  $("#idTableDevice").find("tr").each(function(){
      let tr = $(this);
      let deviceName = tr.find("td:eq(1)").text();
      if (deviceName == did) {
        tr.find("td").eq(3).text(aes);
      }
  });
}

function fWebSocket_init() {
  var stompClient = fWebSocket_connect( function(frame) {
    console.log('Connected: ' + frame);
    stompClient.subscribe('/user/topic/private', function (messageOutput) {
      console.log(messageOutput.body);
      fRx(messageOutput.body);
    });
  });
}

function fRx(message) {
  try {
    message = JSON.parse(message);
    let data = message.data;
    let type = data.type;
    if (type == "console") {
      let text = data.data;
      $('#idConsole').val($('#idConsole').val() + text);
      $('#idConsole').scrollTop($('#idConsole')[0].scrollHeight);
    } if (type == "device-info") {
      let device = data.device;
      fTableDeviceAddRow(device.name, device.hmacPriv, device.sharedKey);
    } if (type == "device-update") {
      let device = data.device;
      fTableUpdateRowAes(device.name, device.sharedKey);
    } if (type == "whitelist-info") {
      let wl = data.wl;
      fTableWLAddRow(wl.pk);
    } else {

    }
  } catch (err) {
    // ignore
  }
}

$("#idBtnDelDev").click(function(){
  $("#idTableDevice").find('input[name="tr-checkbox"]').each(function(){
    if($(this).is(":checked")){
      let tr = $(this).parents("tr");
      let deviceName = tr.find("td:eq(1)").text();
      fWebApi('POST', 'deregister', JSON.stringify({name:deviceName}), function (json) {
        if (json.status === RESP_OK) {
          tr.remove();
        }
      });
    }
  });
});

$("#idBtnUpload").click(function() {
  let file = $('#idInputFile')[0].files[0];
  let fr = new FileReader();
  fr.onload = function(fr) {
    fWebApi('POST', 'wl-upload', JSON.stringify({csv:fr.target.result}), function (json) {
      if (json.status === RESP_OK) {
        //alert("Uploaded successfully");
      } else {
        alert("Failed with error: " + json.message)
      }
    });
  };
  fr.readAsText(file);
  //fr.readAsBinaryString(file); //as bit work with base64 for example upload to server
  //fr.readAsDataURL(file);
});

$("#idBtnDelWL").click(function(){
  $("#idTableWL").find('input[name="tr-checkbox"]').each(function(){
    if($(this).is(":checked")){
      let tr = $(this).parents("tr");
      let pk = tr.find("td:eq(1)").text();
      fWebApi('POST', 'wl-remove', JSON.stringify({pk:pk}), function (json) {
        if (json.status === RESP_OK) {
          tr.remove();
        }
      });
    }
  });
});

function fCheckboxInit() {
  if (user.whitelistisactivated) {
    $("#idCheckboxWL").prop("checked", true);
  } else {
    $("#idCheckboxWL").prop("checked", false);
  }
}

$('#idCheckboxWL').change(function() {
  if($(this).is(":checked")) {
    fWebApi('POST', 'wl-act', JSON.stringify({activated:true}), function (json) {
      if (json.status === RESP_OK) {
      } else {
        alert("Failed with error: " + json.message)
      }
    });
  } else {
    fWebApi('POST', 'wl-act', JSON.stringify({activated:false}), function (json) {
      if (json.status === RESP_OK) {
      } else {
        alert("Failed with error: " + json.message)
      }
    });
  }
});