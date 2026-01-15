<?php

use CodeIgniter\Router\RouteCollection;

/**
 * @var RouteCollection $routes
 */
$routes->get('/', 'Home::index');

$routes->get('1/get-availabilities', 'ApiController::sendAvailability');

$routes->get('1/get-availabilities/', 'ApiController::sendAvailability');

$routes->post('1/reserve', 'ApiController::reserveAvailability');

$routes->post('1/reserve/', 'ApiController::reserveAvailability');

$routes->post('1/cancel-reservation', 'ApiController::cancelReservation');

$routes->post('1/cancel-reservation/', 'ApiController::cancelReservation');

$routes->post('1/book', 'ApiController::bookReservation');

$routes->post('1/book/', 'ApiController::bookReservation');
    
$routes->post('1/cancel-booking', 'ApiController::cancelReservation');
    
$routes->post('1/cancel-booking/', 'ApiController::cancelReservation');

$routes->setAutoRoute(true);
