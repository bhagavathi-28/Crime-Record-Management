
<?php require_once 'controllers/authControllers.php'; ?>

<!DOCTYPE html>
<html>
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width ,initialisation-scale=1"><!-- not clear-->
<meta http-equiv="X-UA-Compatible" content="IE=edge"><!--i donot know-->
  <title>Citizen sign up</title>
  <link rel="stylesheet" href="bootstrap.min.css">
  
  
  <link rel="stylesheet" href="https://www.w3schools.com/w3css/4/w3.css">
<link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/4.7.0/css/font-awesome.min.css">
<link rel="stylesheet" type="text/css" href="citizen sign up.css">
  
</head>
<body>
  <header class="box1">
   <nav id="header-nav" class="navbar navbar-default">
    <div class="container">

      <div class="navbar-header">
        <div class="navbar-brand">
        <a href="#">
                  <h1>Crime record management system</h1>
                </a>
              </div>
      </div>
     <div id="collapsable-nav" class="collapse navbar-collapse">
      <ul id="nav-list" class="nav navbar-nav navbar-right">
         <button type="button" class="btn" onclick="window.location.href='#';">Home</button>
         
      </ul>
    </div>
   
    </div>
   </nav>
    
    
  </header>
   <form class="loginbox" class="box1" action="citizen sign up.php" method="post">
      <h1>Sign up</h1>
      <?php if(count($errors) >0):?>
      <div class="alert alert-danger">
        <?php foreach($errors as $error): ?>
          <li><?php echo $error; ?></li>
        <?php endforeach; ?>
      </div>
    <?php endif; ?>
      <div class="textbox" class="username">
        <input type="text" placeholder="Username" name="username" value="<?php echo $username; ?>" class="name">
        
      </div>
      
      <div class="textbox">
        <input type="email" placeholder="Email" name="email" value="<?php echo $email; ?>">
      </div>
        <div class="textbox">
        <input type="password" placeholder="Password" name="password" value="">
      </div>
      <div class="textbox">
        <input type="password" placeholder="Confirm your password" name="confirmpassword" value="">
      </div>
      
      <div class="textbox">
        <input type="number" placeholder="Phone number" name="phone" value="">
      </div>
      <div class="textbox">
        <label for="fname">Date of birth:</label><br>
        <input type="number" placeholder="month" name="month" value="" class="month">
        <input type="number" placeholder="date" name="date" value="" class="date">
        <input type="number" placeholder="year" name="year" value="" class="year">
      </div>
      
      
      <span><input class="btns" type="submit" name="signup" value="Sign up" ></span>
      </form>
  <footer >
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