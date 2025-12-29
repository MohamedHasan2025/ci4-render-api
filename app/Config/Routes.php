<?php

use CodeIgniter\Router\RouteCollection;

$routes = \Config\Services::routes();

/**
 * @var RouteCollection $routes
 */
    $routes->get('/', 'Home::index');

    $routes->post('get-availabilities', 'ApiController::sendAvailability');
    
    $routes->get('get-availabilities', 'ApiController::sendAvailability'); // optional for GET

    $routes->post('/reserve', 'ApiController::reserveAvailability');

    $routes->post('/cancel-reservation', 'ApiController::cancelReservation');

    $routes->post('/book', 'ApiController::bookReservation');
    
    $routes->post('/cancel-booking', 'ApiController::cancelReservation');
