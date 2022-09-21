
<?php require_once 'controllers/authControllers.php'; 


if(!isset($_SESSION['username'])){
  header('location:citizen login form.php');
  exit();
}



?>
<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width ,initialisation-scale=1"><!-- not clear-->
<meta http-equiv="X-UA-Compatible" content="IE=edge"><!--i donot know-->
  <title>fir form</title>
  
  <link rel="stylesheet" href="bootstrap.min.css">
  <link rel="stylesheet" type="text/css" href="fir form.css">
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
        <a href="#">
                  <h1>Crime record management system</h1>
                </a>
              </div>
      </div>
     <div id="collapsable-nav" class="collapse navbar-collapse">
      <ul id="nav-list" class="nav navbar-nav navbar-right">
   <button class="btn btn-light dropdown-toggle" type="button" data-toggle="dropdown"><i class="fas fa-user"></i>
    <span class="caret"></span></button>
    <ul class="dropdown-menu">
      <li><a href="homepage citizen.php">Home</a></li>
      <li class="divider"></li>
      <li><a href="fir page.php">FIR page</a></li>
      <li class="divider"></li>
      <li><a href="homepage citizen.php?logout=1" >Sign out</a></li>
      </ul>
        </ul>
    </div>
   
    </div>
   </nav>
    
    
  </header>
   <form action="fir form.php" method="post">
    <h1 style="margin:60px;">FIR form</h1>
      <div class="station">
        <p class="b1">Submit to police station:</p>
        <p >
          <div class="col-sm-3" >
          <div style="margin:10px;">District name:</div>
          </div>
          <div class="col-sm-3" >
            <div style="margin:10px;"><input type="text" placeholder="Select district" name="" value="" ></div>
          </div>
          <div class="col-sm-3" >
            <div style="margin:10px;">Police station name:</div>
          </div>
          <div class="col-sm-3" >
            <div style="margin:10px;"><input type="text" placeholder="Select station name" name="" value=""></div>
        </div>
        </p>

      </div>
      <div class="complaintdetails">
        <p>Details of complaint:</p>
        
          <p >
          <div class="col-sm-3" style="line-height:28px;">
            <div style="margin:10px;">Complaint type:</div>
            <div style="margin:10px;">Details of crime:</div>
            <div style="margin:10px;margin-top:55px">Name of accused:</div>
          </div>
          <div class="col-sm-3">
            <div style="margin:10px;"><input type="text" placeholder="Select category" name="" value=""></div>
            <div style="margin:10px;"><textarea class="form-control" rows="3" id="address" ></textarea></div>
            <div style="margin:10px;"><input type="text" placeholder="" name="" value=""></div>
          </div>
          <div class="col-sm-3">
            <div  style="margin:10px;">Occurrence date: </div> 
          </div>
          <div class="col-sm-3">
            <div style="margin:10px;"><input type="date" name="" value="" ></div>
          </div>
        </p>  

      </div>
        <div class="mydetails">
        <p>Your details:</p>
        
            <p >
          <div class="col-sm-3"  style="line-height:28px;">
            <div  style="margin:10px;">Name:</div>
            <div style="margin:10px;">Father name:</div>
            <div style="margin:10px;">ID type:</div>
            <div style="margin:10px;">ID number:</div>
        </div>
          <div class="col-sm-3" >
            <div style="margin:10px;"><input type="text" placeholder="" name="" value=""></div>
            <div style="margin:10px;"><input type="text" name="" value="" ></div>
            <div style="margin:10px;"><input type="text" placeholder="Select ID" name="" value="" ></div>
            <div style="margin:10px;"><input type="tel" name="" value="" ></div>
        </div>
          <div class="col-sm-3" style="line-height:28px;">
            <div style="margin:10px;">Address:</div>
            <div style="margin:10px;margin-top:55px;">Mobile number:</div>
            <div style="margin:10px;">Email:</div> 
        </div>
          <div class="col-sm-3" >
            <div style="margin:10px;"><textarea class="form-control" rows="3" id="address" ></textarea></div>
            <div style="margin:10px;"><input type="tel" name="" value="" ></div>
             <div style="margin:10px;"><input type="email" name="" value="" ></div>
          </div>
        </p> 
            </div>
            <div class="buttons">
            <button class="btn " type="submit" name="submit">Submit</button>
            <?php if(!$_SESSION['complete']):?>
    
        <?php if(count($errors) >0):?>
      <div class="alert alert-danger">
        <?php foreach($errors as $error): ?>
          <li><?php echo $error; ?></li>
        <?php endforeach; ?>
      </div>
    <?php endif; ?>
      <?php endif; ?>

   

    <?php if($_SESSION['complete']):?>
      <div class="alert <?php echo $_SESSION['alert-class1']; ?>">
         <?php echo $_SESSION['message1']; 
         unset($_SESSION['message1']);
         unset($_SESSION['alert-class1']);

         ?>
</div>
    <?php endif; ?>
            <button class="btn " type="button"><a href="fir form.html">Cancel</a></button>
            </div>
   </form>
    
   
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