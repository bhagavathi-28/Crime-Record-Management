
<?php require_once 'controllers/authControllers.php'; 


if(!isset($_SESSION['username'])){
  header('location:citizen login form.php');
  exit();
}

?>
<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width ,initialisation-scale=1"><!-- not clear-->
<meta http-equiv="X-UA-Compatible" content="IE=edge"><!--i donot know-->
  <title>homepage citizen</title>
  
  <link rel="stylesheet" href="bootstrap.min.css">
  <link rel="stylesheet" type="text/css" href="homepage citizen.css">
  <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
<link rel="stylesheet" href="https://use.fontawesome.com/releases/v5.7.0/css/all.css" integrity="sha384-lZN37f5QGtY3VHgisS14W3ExzMWZxybE1SJSEsQp9S+oqd12jhcu+A56Ebc1zFSJ" crossorigin="anonymous">

<script src="https://code.jquery.com/jquery-3.5.1.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/popper.js@1.16.1/dist/umd/popper.min.js"></script>
<script src="https://stackpath.bootstrapcdn.com/bootstrap/4.5.2/js/bootstrap.min.js"></script>
  
</head>
<body>
<header class="box1">
   <nav id="header-nav" class="navbar navbar-default">
    <div class="container">

      <div class="navbar-header">
        <div class="navbar-brand">
        <a href="index.html">
                  <h1>Crime record management system</h1>
                </a>
              </div>
      </div>
     <div id="collapsable-nav" class="collapse navbar-collapse">
      <ul id="nav-list" class="nav navbar-nav navbar-right">
         
         
 
    
    <button class="btn btn-light dropdown-toggle" type="button" data-toggle="dropdown"><i class="fas fa-user"></i>
    <span class="caret"></span></button>
    <ul class="dropdown-menu">
         <?php if(isset($_SESSION['message'])):?>
         <div class="alert <?php echo $_SESSION['alert-class']; ?>">
         <?php echo $_SESSION['message']; 
         unset($_SESSION['message']);
         unset($_SESSION['alert-class']);

         ?>
</div>
<?php endif;?>
    


      <li><a href="homepage citizen.php?logout=1" >Sign out</a></li>
      
    </ul>
          <p style="font-size:10px;color:white;">Welcome, <?php echo $_SESSION['username']; ?></p> 

      </ul>
    </div>
   
    </div>
   </nav>
    
    
  </header>
   <div class="text-box" style="background-color:yellow" >



   <?php if(!$_SESSION['verified']):?>
    <div class="alert alert-warning">
        You need to verify your email account.
        Use the verification link sent to your email - 
        <strong><?php echo $_SESSION['email']; ?></strong>
      </div>

    <?php endif; ?>

    <?php if($_SESSION['verified']):?>
      <button class="btn btn-block btn-lg btn-primary">I am verified!</button>
    <?php endif; ?>




    <section class="col-sm-6" class="section1" style="height:517px;font-size:30px;color:#FFD700" >
      <div style="transform:translateY(150px);line-height:70px;">
      <a href="station details login.html" style="margin:100px;padding:7px;border-bottom: 2px solid #FFD700;">Police station details</a><br>
      <a href="fir page.html" style="margin:100px;padding:7px;border-bottom: 2px solid #FFD700;">FIR's</a><br>
      <a href="emergency no.html" style="margin:100px;padding:7px;border-bottom: 2px solid #FFD700;">Emergency contact numbers</a><br>
    </div>
  </section>
  <section class="col-sm-6" class="section2" style="">
    <img src="css/india.png" >
  </section>
    </div>
    
   
  <footer>
    <div class="container" id="footer">
      <div class="row" >
        
        <section id="hours" class="col-sm-4">
          <span>National emergency number:</span><br>
          <i class="fa fa-phone"></i>: 112<br>
          <hr class="visible-xs">
        </section>
        <section id="hours" class="col-sm-4">
          <span>Police:</span><br>
          <i class="fa fa-phone"></i>: 100<br>
          <hr class="visible-xs">
        </section>
        <section id="hours" class="col-sm-4">
          <span>Women helpline:</span><br>
          <i class="fa fa-phone"></i>: 1091<br>
          <hr class="visible-xs">
        </section>
      </div>
      
    </div>
  </footer>
</body>

</html>