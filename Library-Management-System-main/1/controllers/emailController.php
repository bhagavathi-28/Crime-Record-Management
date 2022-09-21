<?php


require_once 'vendor/autoload.php';
require_once 'config/constants.php';
// Create the Transport
$transport = (new Swift_SmtpTransport('smtp.gmail.com', 465,'ssl'))
  ->setUsername('your username')
  ->setPassword('your password')
;

// Create the Mailer using your created Transport
$mailer = new Swift_Mailer($transport);



function sendVerificationEmail($userEmail,$token)

{

	global $mailer;
$body='<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width ,initialisation-scale=1"><
<meta http-equiv="X-UA-Compatible" content="IE=edge">
<title>Verify email
	</title>
</head>
	<body>
		<div class="wrapper">
			<p>
				Thank you for signing up.Please click on the link below to verify your email.
			</p>
			<a href="https://localhost/1/homepage citizen.php?token=' . $token; '">
				verify your email address
			</a>
		</div>
	</body>
</html>'

// Create a message
$message = (new Swift_Message('Verify your email address'))
  ->setFrom(EMAIL)
  ->setTo($userEmail)
  ->setBody($body,'text/html')
  ;

// Send the message
$result = $mailer->send($message);


}

function sendVerificationEmail($userEmail,$token){

}


?>