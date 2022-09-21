<?php

session_start();
require 'config/db.php';
require_once 'emailController.php';

$errors=array();
$username="";
$email="";



if(isset($_POST['signup'])){

$username=$_POST['username'];
$email=$_POST['email'];
$password=$_POST['password'];
$confirmpassword=$_POST['confirmpassword'];
$phone=$_POST['phone'];
$month=$_POST['month'];
$date=$_POST['date'];
$year=$_POST['year'];

if(empty($username)){
	$errors['username'] = "User is required";
	header("refresh:5;url=citizen sign up.php");
}
if(!filter_var($email,FILTER_VALIDATE_EMAIL)){
	$errors['email'] = "Email address is invalid";
	header("refresh:5;url=citizen sign up.php");
}
if(empty($email)){
	$errors['email'] = "Email is required";
	header("refresh:5;url=citizen sign up.php");
}
if(empty($password)){
	$errors['password'] = "Password is required";
	header("refresh:5;url=citizen sign up.php");
}
if(empty($confirmpassword)){
	$errors['confirmpassword'] = "Confirmation of password is required";
	header("refresh:5;url=citizen sign up.php");
}
if($confirmpassword != $password){
	$errors['passwords'] = "Confirmation password doesn't match password";
	header("refresh:5;url=citizen sign up.php");
}
if(empty($phone)){
	$errors['phone'] = "Contact number is required";
	header("refresh:5;url=citizen sign up.php");
}
if(empty($month)){
	$errors['month'] = "Date of birth is required";
	header("refresh:5;url=citizen sign up.php");
}
if(empty($date)){
	$errors['date'] = "Date of birth is required";
	header("refresh:5;url=citizen sign up.php");
}
if(empty($year)){
	$errors['year'] = "Date of birth is required";
	header("refresh:5;url=citizen sign up.php");
}

$emailquery = "SELECT * FROM sign_in WHERE username='$username' OR email=? LIMIT 1";
$stmt =$conn->prepare($emailquery);
$stmt->bind_param('s',$email);
$stmt->execute();
$result=$stmt->get_result();
$usercount=$result->num_rows;

if($usercount > 0){

	$errors ['email']="Username/email already exists";
} 
if(count($errors)==0){
	$password =password_hash($password,PASSWORD_DEFAULT);
	
	$token = bin2hex(random_bytes(50));
	$verified=false;
$sql="INSERT INTO sign_in(username,email,verified,token,password,phone,month,date,year) VALUES (?,?,?,?,?,?,?,?,?)";
 $stmt =$conn->prepare($sql);
$stmt->bind_param('ssbbsssss',$username,$email,$verified,$token,$password,$phone,$month,$date,$year);
if($stmt->execute()){
//login user
$user_id =$conn->insert_id;
$_SESSION['id']=$user_id;
$_SESSION['username']=$username;
$_SESSION['email']=$email;
$_SESSION['verified']=$verified;

//sendVerificationEmail($email,$token);




//set flash message
$_SESSION['message']="You are now logged in";
$_SESSION['alert-class']="alert-success";
header('location:homepage citizen.php');
exit();
}
else{
	$errors['db_error']="Database error";
}

}










}





//log in 

if(isset($_POST['signin'])){

$username=$_POST['username'];

$password=$_POST['password'];


if(empty($username)){
	$errors['username'] = "Username/email is required";
	
}

if(empty($password)){
	$errors['password'] = "Password is required";
}

if(count($errors) === 0){
 

  $sql="SELECT * FROM sign_in WHERE email=? OR username=? LIMIT 1";
  $stmt =$conn->prepare($sql);
  $stmt->bind_param('ss',$username,$username);
  $stmt->execute();
  $result = $stmt->get_result();
  $user =$result->fetch_assoc();
  
 if(password_verify($password, $user['password'])){
  
 

     
$_SESSION['id']=$user['id'];
$_SESSION['username']=$user['username'];
$_SESSION['email']=$user['email'];
$_SESSION['verified']=$user['verified'];
//set flash message
$_SESSION['message']="You are now logged in";
$_SESSION['alert-class']="alert-success";
header('location:homepage citizen.php');
exit();


 }
 else{

 	$errors['login_fail'] = "Wrong credentials";
 	header("refresh:5;url=citizen login form.php");
 }


}
 
}



//logout user

if(isset($_GET['logout'])){

session_destroy();
unset($_SESSION['id']);
unset($_SESSION['username']);
unset($_SESSION['email']);
unset($_SESSION['verified']);
header('location:citizen login form.php');
exit();
}

//forgot password

if(isset($_POST['forgot-password'])){
 $email=$_POST['email'];
 if(!filter_var($email,FILTER_VALIDATE_EMAIL)){
	$errors['email'] = "Email address is invalid";
	header("refresh:5;url=citizen sign up.php");
}
if(empty($email)){
	$errors['email'] = "Email is required";
	header("refresh:5;url=citizen sign up.php");
}
if(count($errors) ==0){
	$sql="SELECT * FROM sign_in WHERE email=? LIMIT 1";
	 $stmt =$conn->prepare($sql);
  $stmt->bind_param('s',$email);
  $stmt->execute();
  $result = $stmt->get_result();
  $user =$result->fetch_assoc();
  sendPasswordResetLink($email,$token);
  header('location:password_message.php');
}

}


//if user clicks on reset password
if(isset($_POST['reset-password'])){

$password=$_POST['newpassword'];
$passwordConf=$_POST['confirmpassword'];
if(empty($password) || ){
	$errors['password'] = "Password is required";
	header("refresh:5;url=citizen sign up.php");
}
if(empty($confirmpassword)){
	$errors['confirmpassword'] = "Confirmation of password is required";
	header("refresh:5;url=citizen sign up.php");
}
if($confirmpassword != $password){
	$errors['passwords'] = "Confirmation password doesn't match password";
	header("refresh:5;url=citizen sign up.php");
}

$password=password_hash($password, PASSWORD_DEFAULT);
$email=$_SESSION['email'];

if(count($errors) == 0){
	$sql = "UPDATE sign_in SET password='$password' WHERE email='$email'";
    $result = mysqli_query($conn,$sql);
    if($result){
    	header('location:citizen login form.php');
    	exit(0);
    }
}

}












//fir form filling
if(isset($_GET['submit'])){
 
$districtname=$_POST['districtname'];
$stationname=$_POST['stationname'];
$complainttype=$_POST['complainttype'];
$occurencedate=$_POST['occurencedate'];
$deatilsofcrime=$_POST['deatilsofcrime'];
$nameofaccused=$_POST['nameofaccused'];
$name=$_POST['name'];
$fathername=$_POST['fathername'];
$idtype=$_POST['idtype'];
$idnumber=$_POST['idnumber'];
$address=$_POST['address'];
$mobile=$_POST['mobile'];
$emailnew=$_POST['emailnew'];

if(empty($districtname) OR empty($stationname) OR empty($complainttype) OR empty($detailsofcrime)  OR empty($name)  OR empty($fathername)  OR empty($idtype)  OR empty($idnumber)  OR empty($address)  OR empty($mobile)  OR empty($emailnew) ){
	$errors['username'] = "All the fields have to be filled";
	header("refresh:5;url=citizen sign up.php");
}
if(!filter_var($email,FILTER_VALIDATE_EMAIL)){
	$errors['email'] = "Email address is invalid";
	header("refresh:5;url=citizen sign up.php");
}






if(count($errors)===0){
	
	
$fir="INSERT INTO fir_form(username,name,email,address,mobile,fathername,idtype,idnumber,districtname,stationname,complainttype,detailsofcrime,nameofaccused,occurencedate) VALUES (?,?,?,?,?,?,?,?,?)";
 $stmt =$conn->prepare($fir);
$stmt->bind_param('ssssssssssssss',$_SESSION['username'],$name,$emailnew,$address,$mobile,$fathername,$idtype,$idnumber,$districtname,$stationname,$complainttype,$detailsofcrime,$nameofaccused,$occurencedate);
if($stmt->execute()){
//login user
$user_id =$conn->insert_id;




//set flash message
$_SESSION['message1']="Submission successful";
$_SESSION['alert-class1']="alert-success1";
header('location:fir form.php');
exit(0);
}
else{
	$errors['fir_error']="Submission failed";
}

}

}
 
 function resetPassword($token){
global $conn;
$sql ="SELECT *FROM sign_in WHERE token='$token' LIMIT 1";
   $stmt =$conn->prepare($sql);
  
  $stmt->execute();
  $result = $stmt->get_result();
  $user =$result->fetch_assoc();
  $_SESSION['email']=$user['email'];
  header('location:reset_password.php');
  exit(0);
 }

function verifyUser($token)
{
	global $conn;
	$sql ="SELECT * FROM sign_in WHERE token='$token' LIMIT 1";
	$result= mysqli_query($conn,$sql);
	if(mysqli_num_rows($result)>0){
       $user = mysqli_fetch_assoc($result);
       $update_query="UPDATE sign_in SET verified=1 WHERE token='$token'";
       if(mysqli_query($conn,$update_query)){

       	//login user
       	$_SESSION['id']=$user['id'];
       $_SESSION['username']=$user['username'];
        $_SESSION['email']=$user['email'];
        $_SESSION['verified']=1;
        $_SESSION['message']="You email address was successfully verified!";
        $_SESSION['alert-class']="alert-success";
        header('location:homepage citizen.php');
        exit();
       }
       else{
       	echo "User not found";
       }
	}
}





?>