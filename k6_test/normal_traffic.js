import http from 'k6/http';
import { check, sleep, group } from 'k6';

const BASE = __ENV.BASE_URL || 'http://127.0.0.1:51309';

export const options = {
  vus: 5,
  duration: '2m',
};

export default function () {
  group('browse homepage', function () {
    const res = http.get(`${BASE}/`);
    check(res, { 'homepage 200': (r) => r.status === 200 });
    console.log(`homepage → ${res.status}`);
  });

  sleep(Math.random() * 3 + 2);

  group('view product', function () {
    const res = http.get(`${BASE}/product/OLJCESPC7Z`);
    check(res, { 'product 200': (r) => r.status === 200 });
    console.log(`product → ${res.status}`);
  });

  sleep(Math.random() * 4 + 3);

  group('add to cart', function () {
    const res = http.post(`${BASE}/cart`, {
      product_id: 'OLJCESPC7Z',
      quantity: '1',
    });
    check(res, { 'add to cart ok': (r) => r.status === 200 });
    console.log(`add to cart → ${res.status}`);
  });

  sleep(Math.random() * 3 + 2);

  group('view cart', function () {
    const res = http.get(`${BASE}/cart`);
    check(res, { 'cart 200': (r) => r.status === 200 });
    console.log(`cart → ${res.status}`);
  });

  sleep(Math.random() * 3 + 2);

  group('checkout', function () {
    const res = http.post(`${BASE}/cart/checkout`, {
      email: 'someone@example.com',
      street_address: '1600 Amphitheatre Parkway',
      zip_code: '94043',
      city: 'Mountain View',
      state: 'CA',
      country: 'United States',
      credit_card_number: '4432801561520454',
      credit_card_expiration_month: '1',
      credit_card_expiration_year: '2039',
      credit_card_cvv: '672',
    });
    check(res, { 'checkout 200': (r) => r.status === 200 });
    console.log(`checkout → ${res.status}`);
    console.log(`checkout body → ${res.body ? res.body.substring(0, 500) : 'empty'}`);
  });

  sleep(Math.random() * 5 + 5);
}