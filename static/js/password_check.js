
    var pass = document.getElementById("password1");

    var check1 = document.getElementById("check1");
    var check2 = document.getElementById("check2");
    var check3 = document.getElementById("check3");
    var check4 = document.getElementById("check4");
    var check5 = document.getElementById("check5");

    var msg = document.getElementById("message");
    var str = document.getElementById("strength");

    function checkPassword(password, op){
        for(var i = 0; i < password.length; i++){
            switch(op){
                case 1:
                    if(password[i] === password[i].toLowerCase() && password[i] !== password[i].toUpperCase()){
                        return 1;
                    }
                    break;
                case 2:
                    if(password[i] === password[i].toUpperCase() && password[i] !== password[i].toLowerCase()){
                        return 1;
                    }
                    break;
                case 3:
                    if(password[i] >= '0' && password[i] <= '9'){
                        return 1;
                    }
                    break;
                case 4:
                   if("~!@#$%^&*_+=}]?><|".includes(password[i])){
                        return 1;
                   }
            }
        }
        return 0;
    }

    pass.addEventListener('input', () => {
        if(pass.value.length > 0){
            msg.style.display = "block";

            check1.style.display = "block";
            check2.style.display = "block";
            check3.style.display = "block";
            check4.style.display = "block";
            check5.style.display = "block";

            if(pass.value.length >= 8){
                check1.style.color = "#027a00";
            }else{
                check1.style.color = "#595959";
            }

            if(checkPassword(pass.value, 1)){
                check2.style.color = "#027a00";
            }else{
                check2.style.color = "#595959";
            }

            if(checkPassword(pass.value, 2)){
                check3.style.color = "#027a00";
            }else{
                check3.style.color = "#595959";
            }

            if(checkPassword(pass.value, 3)){
                check4.style.color = "#027a00";
            }else{
                check4.style.color = "#595959";
            }

            if(checkPassword(pass.value, 4)){
                check5.style.color = "#027a00";
            }else{
                check5.style.color = "#595959";
            }


            zxc = zxcvbn(pass.value);

            switch(zxc.score){
                case 0:
                    str.innerHTML = "way too weak.\n";
                    msg.style.color = "#a30000";
                    break;
                case 1:
                    str.innerHTML = "too weak.\n";
                    msg.style.color = "#d11f1f";
                    break;
                case 2:
                    str.innerHTML = "medium.\n";
                    msg.style.color = "#e04700";
                    break;
                case 3:
                    str.innerHTML = "strong.\n";
                    msg.style.color = "#027a00";
                    break;
                case 3:
                    str.innerHTML = "very strong.\n";
                    msg.style.color = "#027a00";
                    break;
            }
        }else{
            msg.style.display = "none";
            check1.style.display = "none";
            check2.style.display = "none";
            check3.style.display = "none";
            check4.style.display = "none";
            check5.style.display = "none";

        }


        
    })