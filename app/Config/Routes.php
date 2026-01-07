<?php

use CodeIgniter\Router\RouteCollection;

/**
 * @var RouteCollection $routes
 */
$routes->get('/', 'Home::index');

$routes->get('1/get-availabilities', 'ApiController::sendAvailability');

$routes->post('/reserve', 'ApiController::reserveAvailability');

$routes->post('/cancel-reservation', 'ApiController::cancelReservation');

$routes->post('/book', 'ApiController::bookReservation');
    
$routes->post('/cancel-booking', 'ApiController::cancelReservation');
