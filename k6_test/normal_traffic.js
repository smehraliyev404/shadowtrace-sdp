import http from 'k6/http';
import { check, sleep, group } from 'k6';

const BASE = __ENV.BASE_URL || 'http://localhost:8080';

export const options = {
  vus: 5,
  duration: '2m',
};

export default function () {
  // 1. Browse Homepage
  group('browse homepage', function () {
    const res = http.get(`${BASE}/`);
    check(res, { 'homepage 200': (r) => r.status === 200 });
    console.log(`homepage → ${res.status}`);
  });

  sleep(Math.random() * 3 + 2); // 2-5s human think-time jitter

  // 2. View Product Details
  group('view product', function () {
    const res = http.get(`${BASE}/product/OLJCESPC7Z`);
    check(res, { 'product 200': (r) => r.status === 200 });
    console.log(`product → ${res.status}`);
  });

  sleep(Math.random() * 4 + 3); // 3-7s jitter

  // 3. Add to Cart
  group('add to cart', function () {
    const res = http.post(`${BASE}/cart`, {
      product_id: 'OLJCESPC7Z',
      quantity: '1',
    });
    check(res, { 'add to cart ok': (r) => r.status === 200 });
    console.log(`add to cart → ${res.status}`);
  });

  sleep(Math.random() * 3 + 2);

  // 4. View Cart
  group('view cart', function () {
    const res = http.get(`${BASE}/cart`);
    check(res, { 'cart 200': (r) => r.status === 200 });
    console.log(`cart → ${res.status}`);
  });

  sleep(Math.random() * 3 + 2);

  // 5. Checkout with Dynamic PII & Valid Test Credit Card
  group('checkout', function () {
    const userId = Math.floor(Math.random() * 90000) + 10000;
    const dynamicEmail = `customer_${userId}@example.com`;
    const randomHex = Math.random().toString(36).substring(2, 12);
    const dynamicJwt = `Bearer eyJhY2Nlc3NfdG9rZW4iOiJ4eXoxMjM0NTY3ODkwIiwidXNlciI6ImN1c3RvbWVyXyR7dXNlcklkfSIsInNlc3Npb24iOiIke3JhbmRvbUhleH0ifQ==`;

    // Valid Visa test card that passes Online Boutique's Luhn checksum
    const validTestCard = '4432801561520454';

    const res = http.post(
      `${BASE}/cart/checkout?user_email=${encodeURIComponent(dynamicEmail)}&user_id=${userId}`,
      {
        email: dynamicEmail,
        street_address: `${userId} Innovation Way`,
        zip_code: '94043',
        city: 'Mountain View',
        state: 'CA',
        country: 'United States',
        credit_card_number: validTestCard,
        credit_card_expiration_month: '1',
        credit_card_expiration_year: '2039',
        credit_card_cvv: '672',
      },
      {
        headers: {
          'Authorization': dynamicJwt,
          'X-User-Email': dynamicEmail,
          'X-Customer-Card-Hash': `card_${validTestCard}_secret`,
          'X-Session-Token': `sess_${randomHex}_auth`,
        },
      }
    );
    check(res, { 'checkout 200': (r) => r.status === 200 });
    console.log(`checkout (${dynamicEmail}) → ${res.status}`);
  });

  sleep(Math.random() * 5 + 5);
}
